rule TTP_XOR_QUAD_CurrentVersionRun_3292 {
  strings:
    $key_3292 = { 61 fd [2] 45 f3 [2] 6e df [2] 40 fd [2] 54 e6 [2] 5b fc [2] 45 e1 [2] 47 e0 [2] 5c e6 [2] 40 e1 [2] 5c ce }

  condition:
    any of them
}