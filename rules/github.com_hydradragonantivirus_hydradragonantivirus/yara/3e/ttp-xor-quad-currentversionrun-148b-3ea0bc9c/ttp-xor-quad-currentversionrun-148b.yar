rule TTP_XOR_QUAD_CurrentVersionRun_148b {
  strings:
    $key_148b = { 47 e4 [2] 63 ea [2] 48 c6 [2] 66 e4 [2] 72 ff [2] 7d e5 [2] 63 f8 [2] 61 f9 [2] 7a ff [2] 66 f8 [2] 7a d7 }

  condition:
    any of them
}