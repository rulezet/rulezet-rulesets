rule TTP_XOR_QUAD_CurrentVersionRun_1c92 {
  strings:
    $key_1c92 = { 4f fd [2] 6b f3 [2] 40 df [2] 6e fd [2] 7a e6 [2] 75 fc [2] 6b e1 [2] 69 e0 [2] 72 e6 [2] 6e e1 [2] 72 ce }

  condition:
    any of them
}