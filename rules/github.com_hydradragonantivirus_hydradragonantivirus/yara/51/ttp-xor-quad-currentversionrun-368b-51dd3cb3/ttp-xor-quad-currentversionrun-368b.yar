rule TTP_XOR_QUAD_CurrentVersionRun_368b {
  strings:
    $key_368b = { 65 e4 [2] 41 ea [2] 6a c6 [2] 44 e4 [2] 50 ff [2] 5f e5 [2] 41 f8 [2] 43 f9 [2] 58 ff [2] 44 f8 [2] 58 d7 }

  condition:
    any of them
}