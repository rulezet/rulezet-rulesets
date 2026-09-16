rule TTP_XOR_QUAD_CurrentVersionRun_2c92 {
  strings:
    $key_2c92 = { 7f fd [2] 5b f3 [2] 70 df [2] 5e fd [2] 4a e6 [2] 45 fc [2] 5b e1 [2] 59 e0 [2] 42 e6 [2] 5e e1 [2] 42 ce }

  condition:
    any of them
}