rule TTP_XOR_QUAD_CurrentVersionRun_628b {
  strings:
    $key_628b = { 31 e4 [2] 15 ea [2] 3e c6 [2] 10 e4 [2] 04 ff [2] 0b e5 [2] 15 f8 [2] 17 f9 [2] 0c ff [2] 10 f8 [2] 0c d7 }

  condition:
    any of them
}