rule sig_20161024_393dd03d33a5ebc6d7cd515f1e1a42a7 {
  meta:
    description = "datamaliciousorder - file 20161024_393dd03d33a5ebc6d7cd515f1e1a42a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5f01eb5481ff562348cd9e06ec809fe3b335dd49b5e312c400f104dca046e9c"

  strings:
    $s1 = "} while (gx++ < me);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}