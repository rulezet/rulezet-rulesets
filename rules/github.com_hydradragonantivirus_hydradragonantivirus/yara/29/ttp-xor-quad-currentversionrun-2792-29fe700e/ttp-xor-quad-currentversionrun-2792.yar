rule TTP_XOR_QUAD_CurrentVersionRun_2792 {
  strings:
    $key_2792 = { 74 fd [2] 50 f3 [2] 7b df [2] 55 fd [2] 41 e6 [2] 4e fc [2] 50 e1 [2] 52 e0 [2] 49 e6 [2] 55 e1 [2] 49 ce }

  condition:
    any of them
}