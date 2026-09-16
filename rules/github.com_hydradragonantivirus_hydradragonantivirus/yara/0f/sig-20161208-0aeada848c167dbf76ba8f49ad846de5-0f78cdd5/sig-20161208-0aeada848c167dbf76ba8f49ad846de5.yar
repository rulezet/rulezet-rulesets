rule sig_20161208_0aeada848c167dbf76ba8f49ad846de5 {
  meta:
    description = "datamaliciousorder - file 20161208_0aeada848c167dbf76ba8f49ad846de5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72a2486714c351b1adfaf4706c8181bcb51cdc9f4b33eb3ca97b81a43d7fbb4e"

  strings:
    $s1 = "var vHs8 = new Function(\"vJx6\", '{return vJx6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHg7 = new Function(\"vJx6\"" ascii
    $s2 = "ew Date();vRx2[\"setUTC\"+\"FullYear\"](\"2003\");if (vRx2.getUTCFullYear().toString(10) == \"2003\") {var vEa7 = vJx6.split(\"#" ascii
    $s3 = "var vHs8 = new Function(\"vJx6\", '{return vJx6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHg7 = new Function(\"vJx6\"" ascii
    $s4 = "turn vEa7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}