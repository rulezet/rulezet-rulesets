rule sig_20160824_0ab7f2eeb8b0ef6681b24cbbf2fd807a {
  meta:
    description = "datamaliciousorder - file 20160824_0ab7f2eeb8b0ef6681b24cbbf2fd807a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55f0cd4c87556027040d7f8157840a868405af28b41b644aad32e8a8873eb5ea"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}