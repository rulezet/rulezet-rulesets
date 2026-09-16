rule TTP_XOR_QUAD_CurrentVersionRun_6592 {
  strings:
    $key_6592 = { 36 fd [2] 12 f3 [2] 39 df [2] 17 fd [2] 03 e6 [2] 0c fc [2] 12 e1 [2] 10 e0 [2] 0b e6 [2] 17 e1 [2] 0b ce }

  condition:
    any of them
}