rule TTP_XOR_QUAD_CurrentVersionRun_c292 {
  strings:
    $key_c292 = { 91 fd [2] b5 f3 [2] 9e df [2] b0 fd [2] a4 e6 [2] ab fc [2] b5 e1 [2] b7 e0 [2] ac e6 [2] b0 e1 [2] ac ce }

  condition:
    any of them
}