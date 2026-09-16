rule TTP_XOR_QUAD_CurrentVersionRun_0292 {
  strings:
    $key_0292 = { 51 fd [2] 75 f3 [2] 5e df [2] 70 fd [2] 64 e6 [2] 6b fc [2] 75 e1 [2] 77 e0 [2] 6c e6 [2] 70 e1 [2] 6c ce }

  condition:
    any of them
}