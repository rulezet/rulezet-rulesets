rule TTP_XOR_QUAD_CurrentVersionRun_4192 {
  strings:
    $key_4192 = { 12 fd [2] 36 f3 [2] 1d df [2] 33 fd [2] 27 e6 [2] 28 fc [2] 36 e1 [2] 34 e0 [2] 2f e6 [2] 33 e1 [2] 2f ce }

  condition:
    any of them
}