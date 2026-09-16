rule TTP_XOR_QUAD_CurrentVersionRun_ca92 {
  strings:
    $key_ca92 = { 99 fd [2] bd f3 [2] 96 df [2] b8 fd [2] ac e6 [2] a3 fc [2] bd e1 [2] bf e0 [2] a4 e6 [2] b8 e1 [2] a4 ce }

  condition:
    any of them
}