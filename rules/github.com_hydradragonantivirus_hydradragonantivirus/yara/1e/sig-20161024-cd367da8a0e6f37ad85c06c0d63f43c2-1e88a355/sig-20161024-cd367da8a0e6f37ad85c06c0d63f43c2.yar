rule sig_20161024_cd367da8a0e6f37ad85c06c0d63f43c2 {
  meta:
    description = "datamaliciousorder - file 20161024_cd367da8a0e6f37ad85c06c0d63f43c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d484f067aba60266b3d1bd128fa2e0026eadb2abb32ccf71d671ee60702df0a6"

  strings:
    $s1 = "} while (zo++ < yx);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}