rule TTP_XOR_QUAD_CurrentVersionRun_f58b {
  strings:
    $key_f58b = { a6 e4 [2] 82 ea [2] a9 c6 [2] 87 e4 [2] 93 ff [2] 9c e5 [2] 82 f8 [2] 80 f9 [2] 9b ff [2] 87 f8 [2] 9b d7 }

  condition:
    any of them
}