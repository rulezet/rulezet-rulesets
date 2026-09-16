rule TTP_XOR_QUAD_CurrentVersionRun_0792 {
  strings:
    $key_0792 = { 54 fd [2] 70 f3 [2] 5b df [2] 75 fd [2] 61 e6 [2] 6e fc [2] 70 e1 [2] 72 e0 [2] 69 e6 [2] 75 e1 [2] 69 ce }

  condition:
    any of them
}