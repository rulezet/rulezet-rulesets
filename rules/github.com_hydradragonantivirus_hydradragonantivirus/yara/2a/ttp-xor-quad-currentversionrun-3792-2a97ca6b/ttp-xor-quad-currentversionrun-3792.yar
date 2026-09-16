rule TTP_XOR_QUAD_CurrentVersionRun_3792 {
  strings:
    $key_3792 = { 64 fd [2] 40 f3 [2] 6b df [2] 45 fd [2] 51 e6 [2] 5e fc [2] 40 e1 [2] 42 e0 [2] 59 e6 [2] 45 e1 [2] 59 ce }

  condition:
    any of them
}