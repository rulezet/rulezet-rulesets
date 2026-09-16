rule TTP_XOR_QUAD_CurrentVersionRun_728b {
  strings:
    $key_728b = { 21 e4 [2] 05 ea [2] 2e c6 [2] 00 e4 [2] 14 ff [2] 1b e5 [2] 05 f8 [2] 07 f9 [2] 1c ff [2] 00 f8 [2] 1c d7 }

  condition:
    any of them
}