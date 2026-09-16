rule TTP_XOR_QUAD_CurrentVersionRun_1292 {
  strings:
    $key_1292 = { 41 fd [2] 65 f3 [2] 4e df [2] 60 fd [2] 74 e6 [2] 7b fc [2] 65 e1 [2] 67 e0 [2] 7c e6 [2] 60 e1 [2] 7c ce }

  condition:
    any of them
}