rule sig_20160525_20a534e45ed913ca8635397da5c6279a {
  meta:
    description = "datamaliciousorder - file 20160525_20a534e45ed913ca8635397da5c6279a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "455a86d4746e43dc75a2f634d9ebbb604d1f2abacbe19f0c9438c6209766fa43"

  strings:
    $s1 = "lock noitcnuf([tpircSW{ )e( hctac" fullword ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}