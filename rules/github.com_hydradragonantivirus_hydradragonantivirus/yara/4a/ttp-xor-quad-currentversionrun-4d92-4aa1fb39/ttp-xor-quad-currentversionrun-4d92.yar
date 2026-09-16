rule TTP_XOR_QUAD_CurrentVersionRun_4d92 {
  strings:
    $key_4d92 = { 1e fd [2] 3a f3 [2] 11 df [2] 3f fd [2] 2b e6 [2] 24 fc [2] 3a e1 [2] 38 e0 [2] 23 e6 [2] 3f e1 [2] 23 ce }

  condition:
    any of them
}