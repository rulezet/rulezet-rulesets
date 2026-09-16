rule TTP_XOR_QUAD_CurrentVersionRun_1592 {
  strings:
    $key_1592 = { 46 fd [2] 62 f3 [2] 49 df [2] 67 fd [2] 73 e6 [2] 7c fc [2] 62 e1 [2] 60 e0 [2] 7b e6 [2] 67 e1 [2] 7b ce }

  condition:
    any of them
}