rule TTP_XOR_QUAD_CurrentVersionRun_648b {
  strings:
    $key_648b = { 37 e4 [2] 13 ea [2] 38 c6 [2] 16 e4 [2] 02 ff [2] 0d e5 [2] 13 f8 [2] 11 f9 [2] 0a ff [2] 16 f8 [2] 0a d7 }

  condition:
    any of them
}