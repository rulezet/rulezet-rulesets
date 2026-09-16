rule TTP_XOR_QUAD_CurrentVersionRun_3b92 {
  strings:
    $key_3b92 = { 68 fd [2] 4c f3 [2] 67 df [2] 49 fd [2] 5d e6 [2] 52 fc [2] 4c e1 [2] 4e e0 [2] 55 e6 [2] 49 e1 [2] 55 ce }

  condition:
    any of them
}