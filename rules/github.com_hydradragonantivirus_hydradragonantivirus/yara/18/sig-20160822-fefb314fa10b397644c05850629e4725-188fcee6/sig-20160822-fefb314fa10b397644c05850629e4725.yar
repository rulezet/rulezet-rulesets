rule sig_20160822_fefb314fa10b397644c05850629e4725 {
  meta:
    description = "datamaliciousorder - file 20160822_fefb314fa10b397644c05850629e4725.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "670737c6feb5ec7abf403ce86720d7b16eacc161822ec0008edb39a9c747b6cd"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}