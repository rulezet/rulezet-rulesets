rule sig_20161024_d118d6c66b655787f86a7ffa235e462f {
  meta:
    description = "datamaliciousorder - file 20161024_d118d6c66b655787f86a7ffa235e462f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "092859ba78b0a43eb8c68e12fbfab673f55d425c6aec904ef22cf190d4adccf1"

  strings:
    $s1 = "} while (ve++ < hf);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}