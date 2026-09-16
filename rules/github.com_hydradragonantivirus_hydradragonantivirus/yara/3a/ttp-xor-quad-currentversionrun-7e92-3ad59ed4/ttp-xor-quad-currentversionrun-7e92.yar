rule TTP_XOR_QUAD_CurrentVersionRun_7e92 {
  strings:
    $key_7e92 = { 2d fd [2] 09 f3 [2] 22 df [2] 0c fd [2] 18 e6 [2] 17 fc [2] 09 e1 [2] 0b e0 [2] 10 e6 [2] 0c e1 [2] 10 ce }

  condition:
    any of them
}