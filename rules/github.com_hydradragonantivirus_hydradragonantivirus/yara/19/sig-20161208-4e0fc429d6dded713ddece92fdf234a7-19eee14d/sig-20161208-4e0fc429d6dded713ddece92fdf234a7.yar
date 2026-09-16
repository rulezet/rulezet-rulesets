rule sig_20161208_4e0fc429d6dded713ddece92fdf234a7 {
  meta:
    description = "datamaliciousorder - file 20161208_4e0fc429d6dded713ddece92fdf234a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "857d8ef1301b0ebb6bb7c23ce033b79d5f7fa9f5807cfa8dc4d46487844c5019"

  strings:
    $s1 = "var vMm3 = new Function(\"vVk2\", '{return vVk2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCf6 = new Function(\"vVk2\"" ascii
    $s2 = "new Date();vJIi4[\"setUTC\"+\"FullYear\"](\"2003\");if (vJIi4.getUTCFullYear().toString(10) == \"2003\") {var vNn5 = vVk2.split(" ascii
    $s3 = "var vMm3 = new Function(\"vVk2\", '{return vVk2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCf6 = new Function(\"vVk2\"" ascii
    $s4 = " return vNn5.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}