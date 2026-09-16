rule sig_20160824_4096220b1a098fcd2e51d4f7a06b8b6d {
  meta:
    description = "datamaliciousorder - file 20160824_4096220b1a098fcd2e51d4f7a06b8b6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c140bc9d7dfb2b19936e7641c6793a6583a1c2661fbad30809fd772e09dfaab7"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}