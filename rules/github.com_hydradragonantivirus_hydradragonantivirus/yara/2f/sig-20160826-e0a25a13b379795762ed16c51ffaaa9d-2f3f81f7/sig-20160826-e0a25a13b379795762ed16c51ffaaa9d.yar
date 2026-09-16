rule sig_20160826_e0a25a13b379795762ed16c51ffaaa9d {
  meta:
    description = "datamaliciousorder - file 20160826_e0a25a13b379795762ed16c51ffaaa9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efd72bc1a70e486a08215ca018b4834597787d4bd53aae3a0b3cedba13fe7cfe"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4d\",\"\\x6c\",\"\\x3d\",\"\\x22\",\"\\x65\",\"\\x2b" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}