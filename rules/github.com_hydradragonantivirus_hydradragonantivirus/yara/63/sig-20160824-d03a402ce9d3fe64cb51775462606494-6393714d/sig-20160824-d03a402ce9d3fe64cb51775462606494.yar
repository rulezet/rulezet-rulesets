rule sig_20160824_d03a402ce9d3fe64cb51775462606494 {
  meta:
    description = "datamaliciousorder - file 20160824_d03a402ce9d3fe64cb51775462606494.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2330e41476aa9908ae79d6cd17a58c8e3af5db9dc6d987d89ab38b18c7031e51"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}