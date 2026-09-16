rule TTP_XOR_QUAD_CurrentVersionRun_e792 {
  strings:
    $key_e792 = { b4 fd [2] 90 f3 [2] bb df [2] 95 fd [2] 81 e6 [2] 8e fc [2] 90 e1 [2] 92 e0 [2] 89 e6 [2] 95 e1 [2] 89 ce }

  condition:
    any of them
}