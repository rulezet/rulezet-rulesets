rule sig_20161024_d6e327629f5840fa592caf2b79e628ef {
  meta:
    description = "datamaliciousorder - file 20161024_d6e327629f5840fa592caf2b79e628ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11d275c281ce8a2e69d96641872521eda6e05bb1eee537b93ca37ced56335aea"

  strings:
    $s1 = "} while (xn++ < oc);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}