rule sig_20160823_1c67d680912683455ece24296f09c065 {
  meta:
    description = "datamaliciousorder - file 20160823_1c67d680912683455ece24296f09c065.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "340bbd07c9bfe10be88854dfa4435cd588d775f95f597b3e6c14f6d8a9756a1c"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}