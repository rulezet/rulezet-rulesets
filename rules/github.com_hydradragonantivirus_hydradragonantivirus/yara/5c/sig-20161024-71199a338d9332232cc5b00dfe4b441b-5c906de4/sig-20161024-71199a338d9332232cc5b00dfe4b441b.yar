rule sig_20161024_71199a338d9332232cc5b00dfe4b441b {
  meta:
    description = "datamaliciousorder - file 20161024_71199a338d9332232cc5b00dfe4b441b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ee191969d21238a0eceb5baeb316c895c74eb96fc7cacfef937a6cff9551e5b"

  strings:
    $s1 = "} while (ij++ < ex);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}