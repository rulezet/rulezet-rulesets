rule TTP_XOR_QUAD_CurrentVersionRun_e592 {
  strings:
    $key_e592 = { b6 fd [2] 92 f3 [2] b9 df [2] 97 fd [2] 83 e6 [2] 8c fc [2] 92 e1 [2] 90 e0 [2] 8b e6 [2] 97 e1 [2] 8b ce }

  condition:
    any of them
}