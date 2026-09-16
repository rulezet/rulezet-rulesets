rule TTP_XOR_QUAD_CurrentVersionRun_478b {
  strings:
    $key_478b = { 14 e4 [2] 30 ea [2] 1b c6 [2] 35 e4 [2] 21 ff [2] 2e e5 [2] 30 f8 [2] 32 f9 [2] 29 ff [2] 35 f8 [2] 29 d7 }

  condition:
    any of them
}