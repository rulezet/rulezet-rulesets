rule TTP_XOR_QUAD_CurrentVersionRun_4a92 {
  strings:
    $key_4a92 = { 19 fd [2] 3d f3 [2] 16 df [2] 38 fd [2] 2c e6 [2] 23 fc [2] 3d e1 [2] 3f e0 [2] 24 e6 [2] 38 e1 [2] 24 ce }

  condition:
    any of them
}