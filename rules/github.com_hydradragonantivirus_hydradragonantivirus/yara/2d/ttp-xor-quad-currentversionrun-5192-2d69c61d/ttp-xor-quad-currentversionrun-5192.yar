rule TTP_XOR_QUAD_CurrentVersionRun_5192 {
  strings:
    $key_5192 = { 02 fd [2] 26 f3 [2] 0d df [2] 23 fd [2] 37 e6 [2] 38 fc [2] 26 e1 [2] 24 e0 [2] 3f e6 [2] 23 e1 [2] 3f ce }

  condition:
    any of them
}