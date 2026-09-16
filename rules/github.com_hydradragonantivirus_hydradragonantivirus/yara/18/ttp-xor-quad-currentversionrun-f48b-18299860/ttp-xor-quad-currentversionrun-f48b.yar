rule TTP_XOR_QUAD_CurrentVersionRun_f48b {
  strings:
    $key_f48b = { a7 e4 [2] 83 ea [2] a8 c6 [2] 86 e4 [2] 92 ff [2] 9d e5 [2] 83 f8 [2] 81 f9 [2] 9a ff [2] 86 f8 [2] 9a d7 }

  condition:
    any of them
}