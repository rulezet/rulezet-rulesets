rule TTP_XOR_QUAD_CurrentVersionRun_7287 {
  strings:
    $key_7287 = { 21 e8 [2] 05 e6 [2] 2e ca [2] 00 e8 [2] 14 f3 [2] 1b e9 [2] 05 f4 [2] 07 f5 [2] 1c f3 [2] 00 f4 [2] 1c db }

  condition:
    any of them
}