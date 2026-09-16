rule TTP_XOR_QUAD_CurrentVersionRun_5692 {
  strings:
    $key_5692 = { 05 fd [2] 21 f3 [2] 0a df [2] 24 fd [2] 30 e6 [2] 3f fc [2] 21 e1 [2] 23 e0 [2] 38 e6 [2] 24 e1 [2] 38 ce }

  condition:
    any of them
}