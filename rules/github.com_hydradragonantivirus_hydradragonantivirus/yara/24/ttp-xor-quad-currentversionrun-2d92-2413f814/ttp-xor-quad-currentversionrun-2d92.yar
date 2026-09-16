rule TTP_XOR_QUAD_CurrentVersionRun_2d92 {
  strings:
    $key_2d92 = { 7e fd [2] 5a f3 [2] 71 df [2] 5f fd [2] 4b e6 [2] 44 fc [2] 5a e1 [2] 58 e0 [2] 43 e6 [2] 5f e1 [2] 43 ce }

  condition:
    any of them
}