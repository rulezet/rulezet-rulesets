rule TTP_XOR_QUAD_CurrentVersionRun_2b92 {
  strings:
    $key_2b92 = { 78 fd [2] 5c f3 [2] 77 df [2] 59 fd [2] 4d e6 [2] 42 fc [2] 5c e1 [2] 5e e0 [2] 45 e6 [2] 59 e1 [2] 45 ce }

  condition:
    any of them
}