rule TTP_XOR_QUAD_CurrentVersionRun_4b92 {
  strings:
    $key_4b92 = { 18 fd [2] 3c f3 [2] 17 df [2] 39 fd [2] 2d e6 [2] 22 fc [2] 3c e1 [2] 3e e0 [2] 25 e6 [2] 39 e1 [2] 25 ce }

  condition:
    any of them
}