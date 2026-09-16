rule TTP_XOR_QUAD_CurrentVersionRun_7285 {
  strings:
    $key_7285 = { 21 ea [2] 05 e4 [2] 2e c8 [2] 00 ea [2] 14 f1 [2] 1b eb [2] 05 f6 [2] 07 f7 [2] 1c f1 [2] 00 f6 [2] 1c d9 }

  condition:
    any of them
}