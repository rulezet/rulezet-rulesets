rule TTP_XOR_QUAD_CurrentVersionRun_5e92 {
  strings:
    $key_5e92 = { 0d fd [2] 29 f3 [2] 02 df [2] 2c fd [2] 38 e6 [2] 37 fc [2] 29 e1 [2] 2b e0 [2] 30 e6 [2] 2c e1 [2] 30 ce }

  condition:
    any of them
}