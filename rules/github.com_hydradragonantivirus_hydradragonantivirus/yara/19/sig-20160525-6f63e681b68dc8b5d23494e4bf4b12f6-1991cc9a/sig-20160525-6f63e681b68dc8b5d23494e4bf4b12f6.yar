rule sig_20160525_6f63e681b68dc8b5d23494e4bf4b12f6 {
  meta:
    description = "datamaliciousorder - file 20160525_6f63e681b68dc8b5d23494e4bf4b12f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27521502a0a7a2f73db819aa43db8ea03c364d0e98e51b9ab5464d9447257815"

  strings:
    $s1 = "dare nruter{)(keppele noitcnuf(+me+dnenoisilloce+))(};gsme nruter{)(suidarelcitrape noitcnuf( + eixode+cthd + )tsilslianbmuhtod(" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}