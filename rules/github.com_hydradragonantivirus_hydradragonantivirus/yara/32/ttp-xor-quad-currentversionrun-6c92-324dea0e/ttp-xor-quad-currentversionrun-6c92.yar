rule TTP_XOR_QUAD_CurrentVersionRun_6c92 {
  strings:
    $key_6c92 = { 3f fd [2] 1b f3 [2] 30 df [2] 1e fd [2] 0a e6 [2] 05 fc [2] 1b e1 [2] 19 e0 [2] 02 e6 [2] 1e e1 [2] 02 ce }

  condition:
    any of them
}