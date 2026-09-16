rule TTP_XOR_QUAD_CurrentVersionRun_4792 {
  strings:
    $key_4792 = { 14 fd [2] 30 f3 [2] 1b df [2] 35 fd [2] 21 e6 [2] 2e fc [2] 30 e1 [2] 32 e0 [2] 29 e6 [2] 35 e1 [2] 29 ce }

  condition:
    any of them
}