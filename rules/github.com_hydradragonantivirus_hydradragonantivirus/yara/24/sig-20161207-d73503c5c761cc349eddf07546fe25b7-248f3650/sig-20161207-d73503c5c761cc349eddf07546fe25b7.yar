rule sig_20161207_d73503c5c761cc349eddf07546fe25b7 {
  meta:
    description = "datamaliciousorder - file 20161207_d73503c5c761cc349eddf07546fe25b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "068a300ddfb2ea21429d1ce3d7104cfdc019309f0d433081a0f025deed64880f"

  strings:
    $s1 = " = new Date();vMFf8[\"setUTCFullYear\"](\"2003\");if (vMFf8.getUTCFullYear().toString(10) == \"2003\") {var vZXg8 = vOZv4.split(" ascii
    $s2 = "var vJb5 = new Function(\"vOZv4\", '{return vOZv4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTh5 = new Function(\"vOZv" ascii
    $s3 = "var vJb5 = new Function(\"vOZv4\", '{return vOZv4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTh5 = new Function(\"vOZv" ascii
    $s4 = "); return vZXg8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}