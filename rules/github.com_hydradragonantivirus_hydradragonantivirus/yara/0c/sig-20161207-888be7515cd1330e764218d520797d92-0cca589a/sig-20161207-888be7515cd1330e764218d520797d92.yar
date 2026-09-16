rule sig_20161207_888be7515cd1330e764218d520797d92 {
  meta:
    description = "datamaliciousorder - file 20161207_888be7515cd1330e764218d520797d92.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae673955a3e0547cd2cf1101fd599b888299f28ee6c54d498282f96a4f74eddd"

  strings:
    $s1 = "var vOg6 = new Function(\"vBi8\", '{return vBi8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXp6 = new Function(\"vBi8\"" ascii
    $s2 = "ew Date();vZl4[\"setUTCFullYear\"](\"2003\");if (vZl4.getUTCFullYear().toString(10) == \"2003\") {var vAw9 = vBi8.split(\"####\"" ascii
    $s3 = "var vOg6 = new Function(\"vBi8\", '{return vBi8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXp6 = new Function(\"vBi8\"" ascii
    $s4 = "n vAw9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}