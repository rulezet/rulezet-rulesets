rule TTP_XOR_QUAD_CurrentVersionRun_2592 {
  strings:
    $key_2592 = { 76 fd [2] 52 f3 [2] 79 df [2] 57 fd [2] 43 e6 [2] 4c fc [2] 52 e1 [2] 50 e0 [2] 4b e6 [2] 57 e1 [2] 4b ce }

  condition:
    any of them
}