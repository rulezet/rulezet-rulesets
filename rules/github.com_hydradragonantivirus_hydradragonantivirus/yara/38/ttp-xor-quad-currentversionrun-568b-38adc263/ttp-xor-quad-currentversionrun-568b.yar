rule TTP_XOR_QUAD_CurrentVersionRun_568b {
  strings:
    $key_568b = { 05 e4 [2] 21 ea [2] 0a c6 [2] 24 e4 [2] 30 ff [2] 3f e5 [2] 21 f8 [2] 23 f9 [2] 38 ff [2] 24 f8 [2] 38 d7 }

  condition:
    any of them
}