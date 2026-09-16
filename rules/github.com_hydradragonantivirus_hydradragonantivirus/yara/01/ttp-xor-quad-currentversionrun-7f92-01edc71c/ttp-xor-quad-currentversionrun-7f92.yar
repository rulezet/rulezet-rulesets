rule TTP_XOR_QUAD_CurrentVersionRun_7f92 {
  strings:
    $key_7f92 = { 2c fd [2] 08 f3 [2] 23 df [2] 0d fd [2] 19 e6 [2] 16 fc [2] 08 e1 [2] 0a e0 [2] 11 e6 [2] 0d e1 [2] 11 ce }

  condition:
    any of them
}