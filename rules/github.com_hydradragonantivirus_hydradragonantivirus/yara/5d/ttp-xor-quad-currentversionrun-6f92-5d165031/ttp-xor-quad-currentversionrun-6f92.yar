rule TTP_XOR_QUAD_CurrentVersionRun_6f92 {
  strings:
    $key_6f92 = { 3c fd [2] 18 f3 [2] 33 df [2] 1d fd [2] 09 e6 [2] 06 fc [2] 18 e1 [2] 1a e0 [2] 01 e6 [2] 1d e1 [2] 01 ce }

  condition:
    any of them
}