rule sig_20160824_ae83800bfff2a3c62c4312cb370bd935 {
  meta:
    description = "datamaliciousorder - file 20160824_ae83800bfff2a3c62c4312cb370bd935.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db16eec6b974048a436421b7db1f916a40e0dda2c40e8a301c122d5ef7e61e36"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}