rule sig_20160823_5fe96a4f6699c0896e74a8abe9af3cf1 {
  meta:
    description = "datamaliciousorder - file 20160823_5fe96a4f6699c0896e74a8abe9af3cf1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adb90f98ea533ed084cf6430cfeace23363b503dfbc4b2ed0f7fc7314d257490"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}