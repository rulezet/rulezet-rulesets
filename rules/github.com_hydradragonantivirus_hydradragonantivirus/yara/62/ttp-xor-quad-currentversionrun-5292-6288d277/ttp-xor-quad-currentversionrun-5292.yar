rule TTP_XOR_QUAD_CurrentVersionRun_5292 {
  strings:
    $key_5292 = { 01 fd [2] 25 f3 [2] 0e df [2] 20 fd [2] 34 e6 [2] 3b fc [2] 25 e1 [2] 27 e0 [2] 3c e6 [2] 20 e1 [2] 3c ce }

  condition:
    any of them
}