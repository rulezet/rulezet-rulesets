rule TTP_XOR_QUAD_CurrentVersionRun_5f92 {
  strings:
    $key_5f92 = { 0c fd [2] 28 f3 [2] 03 df [2] 2d fd [2] 39 e6 [2] 36 fc [2] 28 e1 [2] 2a e0 [2] 31 e6 [2] 2d e1 [2] 31 ce }

  condition:
    any of them
}