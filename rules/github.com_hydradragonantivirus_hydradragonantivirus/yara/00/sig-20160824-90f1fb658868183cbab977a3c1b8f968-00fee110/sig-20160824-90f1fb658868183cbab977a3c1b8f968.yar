rule sig_20160824_90f1fb658868183cbab977a3c1b8f968 {
  meta:
    description = "datamaliciousorder - file 20160824_90f1fb658868183cbab977a3c1b8f968.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d31e7c6ca591fe7419f1664ae1a0b9c0f8d1a170d70415e634538c34c5cc304b"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}