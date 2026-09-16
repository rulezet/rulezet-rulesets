rule TTP_XOR_QUAD_CurrentVersionRun_278b {
  strings:
    $key_278b = { 74 e4 [2] 50 ea [2] 7b c6 [2] 55 e4 [2] 41 ff [2] 4e e5 [2] 50 f8 [2] 52 f9 [2] 49 ff [2] 55 f8 [2] 49 d7 }

  condition:
    any of them
}