rule sig_20161024_0fbd76403c597744cfb5f08560828d75 {
  meta:
    description = "datamaliciousorder - file 20161024_0fbd76403c597744cfb5f08560828d75.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa77c64b93483306337e97d995bce06a94d4f66b8739c39abbec525fe496b923"

  strings:
    $s1 = "} while (bu++ < dl);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}