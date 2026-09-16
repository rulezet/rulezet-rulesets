rule sig_20160824_175f71503d7f9c5efd3b8c6698bae242 {
  meta:
    description = "datamaliciousorder - file 20160824_175f71503d7f9c5efd3b8c6698bae242.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47a1bdb87e29e907a0944b321caec72ede8ce784c295b4a245f68f3a275a0aff"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}