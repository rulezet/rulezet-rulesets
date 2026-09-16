rule TTP_XOR_QUAD_CurrentVersionRun_4292 {
  strings:
    $key_4292 = { 11 fd [2] 35 f3 [2] 1e df [2] 30 fd [2] 24 e6 [2] 2b fc [2] 35 e1 [2] 37 e0 [2] 2c e6 [2] 30 e1 [2] 2c ce }

  condition:
    any of them
}