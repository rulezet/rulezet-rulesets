rule sig_20160904_91d30233f9170bb9db3386020803538a {
  meta:
    description = "datamaliciousorder - file 20160904_91d30233f9170bb9db3386020803538a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89fb77b146553d06730a1fb6f0bc754e0611181b512159402de38439b09fd301"

  strings:
    $s1 = "      return WScript[WRZDISWBT+SCFBCE+LEBRGBAP+EGYHKYK+VRCTUND+MCHFECVGX+FEDWIZFC+YGZMN+AMUCEQYKL+GCIKGB+WSEVG+MHZGFYTFT](IESWAP" ascii
    $s2 = "      return WScript[WRZDISWBT+SCFBCE+LEBRGBAP+EGYHKYK+VRCTUND+MCHFECVGX+FEDWIZFC+YGZMN+AMUCEQYKL+GCIKGB+WSEVG+MHZGFYTFT](IESWAP" ascii

  condition:
    uint16(0) == 0x2f2f and
    all of them
}