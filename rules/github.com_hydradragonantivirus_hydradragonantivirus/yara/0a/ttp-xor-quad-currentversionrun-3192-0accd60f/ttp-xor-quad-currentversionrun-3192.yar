rule TTP_XOR_QUAD_CurrentVersionRun_3192 {
  strings:
    $key_3192 = { 62 fd [2] 46 f3 [2] 6d df [2] 43 fd [2] 57 e6 [2] 58 fc [2] 46 e1 [2] 44 e0 [2] 5f e6 [2] 43 e1 [2] 5f ce }

  condition:
    any of them
}