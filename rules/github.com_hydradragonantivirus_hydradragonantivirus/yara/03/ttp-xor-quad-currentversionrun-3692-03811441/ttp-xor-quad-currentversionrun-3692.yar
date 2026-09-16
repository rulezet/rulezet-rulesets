rule TTP_XOR_QUAD_CurrentVersionRun_3692 {
  strings:
    $key_3692 = { 65 fd [2] 41 f3 [2] 6a df [2] 44 fd [2] 50 e6 [2] 5f fc [2] 41 e1 [2] 43 e0 [2] 58 e6 [2] 44 e1 [2] 58 ce }

  condition:
    any of them
}