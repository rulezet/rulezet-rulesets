rule sig_20161207_d32518d761f2eea6240ddc02b625f4e0 {
  meta:
    description = "datamaliciousorder - file 20161207_d32518d761f2eea6240ddc02b625f4e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07f4c109fa977a4ec7e54e96bdc006fd1e5dc54b56b18cf36ca662d80b7989c0"

  strings:
    $s1 = "var vVJz6 = new Function(\"vLNd7\", '{return vLNd7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOLa6 = new Function(\"vL" ascii
    $s2 = "70 = new Date();vRu70[\"setUTCFullYear\"](\"2003\");if (vRu70.getUTCFullYear().toString(10) == \"2003\") {var vJLr0 = vLNd7.spli" ascii
    $s3 = "var vVJz6 = new Function(\"vLNd7\", '{return vLNd7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOLa6 = new Function(\"vL" ascii
    $s4 = "#\"); return vJLr0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}