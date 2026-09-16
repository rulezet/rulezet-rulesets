rule TTP_XOR_QUAD_CurrentVersionRun_268b {
  strings:
    $key_268b = { 75 e4 [2] 51 ea [2] 7a c6 [2] 54 e4 [2] 40 ff [2] 4f e5 [2] 51 f8 [2] 53 f9 [2] 48 ff [2] 54 f8 [2] 48 d7 }

  condition:
    any of them
}