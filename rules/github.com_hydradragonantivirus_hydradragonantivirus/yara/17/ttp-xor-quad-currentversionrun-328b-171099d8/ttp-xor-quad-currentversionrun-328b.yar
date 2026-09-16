rule TTP_XOR_QUAD_CurrentVersionRun_328b {
  strings:
    $key_328b = { 61 e4 [2] 45 ea [2] 6e c6 [2] 40 e4 [2] 54 ff [2] 5b e5 [2] 45 f8 [2] 47 f9 [2] 5c ff [2] 40 f8 [2] 5c d7 }

  condition:
    any of them
}