rule TTP_XOR_QUAD_CurrentVersionRun_4492 {
  strings:
    $key_4492 = { 17 fd [2] 33 f3 [2] 18 df [2] 36 fd [2] 22 e6 [2] 2d fc [2] 33 e1 [2] 31 e0 [2] 2a e6 [2] 36 e1 [2] 2a ce }

  condition:
    any of them
}