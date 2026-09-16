rule TTP_XOR_QUAD_CurrentVersionRun_eb92 {
  strings:
    $key_eb92 = { b8 fd [2] 9c f3 [2] b7 df [2] 99 fd [2] 8d e6 [2] 82 fc [2] 9c e1 [2] 9e e0 [2] 85 e6 [2] 99 e1 [2] 85 ce }

  condition:
    any of them
}