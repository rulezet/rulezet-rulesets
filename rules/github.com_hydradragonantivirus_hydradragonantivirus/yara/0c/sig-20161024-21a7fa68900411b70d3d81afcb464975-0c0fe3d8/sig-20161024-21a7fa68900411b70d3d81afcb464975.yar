rule sig_20161024_21a7fa68900411b70d3d81afcb464975 {
  meta:
    description = "datamaliciousorder - file 20161024_21a7fa68900411b70d3d81afcb464975.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8fe5e80d0b47ff928ceafabc66ae918a56aa1c215758a5a23be2e43caff99c5"

  strings:
    $s1 = "} while (ca++ < xl);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}