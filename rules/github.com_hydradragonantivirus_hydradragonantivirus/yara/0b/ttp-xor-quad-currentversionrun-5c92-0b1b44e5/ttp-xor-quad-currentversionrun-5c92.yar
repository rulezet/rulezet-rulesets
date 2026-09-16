rule TTP_XOR_QUAD_CurrentVersionRun_5c92 {
  strings:
    $key_5c92 = { 0f fd [2] 2b f3 [2] 00 df [2] 2e fd [2] 3a e6 [2] 35 fc [2] 2b e1 [2] 29 e0 [2] 32 e6 [2] 2e e1 [2] 32 ce }

  condition:
    any of them
}