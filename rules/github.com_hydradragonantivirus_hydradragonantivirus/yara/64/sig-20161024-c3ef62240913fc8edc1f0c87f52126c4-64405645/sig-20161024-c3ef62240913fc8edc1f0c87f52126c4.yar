rule sig_20161024_c3ef62240913fc8edc1f0c87f52126c4 {
  meta:
    description = "datamaliciousorder - file 20161024_c3ef62240913fc8edc1f0c87f52126c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f5f7ade53feaa1aa2c4c7a5680dbbb71935dda8dd2074bcb839cb36defeb30b"

  strings:
    $s1 = "} while (md++ < if0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}