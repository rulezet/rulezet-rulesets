rule TTP_XOR_QUAD_CurrentVersionRun_6b92 {
  strings:
    $key_6b92 = { 38 fd [2] 1c f3 [2] 37 df [2] 19 fd [2] 0d e6 [2] 02 fc [2] 1c e1 [2] 1e e0 [2] 05 e6 [2] 19 e1 [2] 05 ce }

  condition:
    any of them
}