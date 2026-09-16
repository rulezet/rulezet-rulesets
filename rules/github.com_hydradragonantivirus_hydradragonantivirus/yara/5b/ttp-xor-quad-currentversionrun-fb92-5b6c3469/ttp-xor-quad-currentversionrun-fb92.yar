rule TTP_XOR_QUAD_CurrentVersionRun_fb92 {
  strings:
    $key_fb92 = { a8 fd [2] 8c f3 [2] a7 df [2] 89 fd [2] 9d e6 [2] 92 fc [2] 8c e1 [2] 8e e0 [2] 95 e6 [2] 89 e1 [2] 95 ce }

  condition:
    any of them
}