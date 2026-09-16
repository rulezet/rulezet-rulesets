rule sig_20160824_59e52a35ec7743215b2dd583e2516508 {
  meta:
    description = "datamaliciousorder - file 20160824_59e52a35ec7743215b2dd583e2516508.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a28e5e66e7a40e41157889e57232404db0d943339486cf4785088fbf32abd2d"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}