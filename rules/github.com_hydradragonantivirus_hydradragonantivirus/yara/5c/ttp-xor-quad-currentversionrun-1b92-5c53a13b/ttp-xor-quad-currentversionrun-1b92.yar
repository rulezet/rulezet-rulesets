rule TTP_XOR_QUAD_CurrentVersionRun_1b92 {
  strings:
    $key_1b92 = { 48 fd [2] 6c f3 [2] 47 df [2] 69 fd [2] 7d e6 [2] 72 fc [2] 6c e1 [2] 6e e0 [2] 75 e6 [2] 69 e1 [2] 75 ce }

  condition:
    any of them
}