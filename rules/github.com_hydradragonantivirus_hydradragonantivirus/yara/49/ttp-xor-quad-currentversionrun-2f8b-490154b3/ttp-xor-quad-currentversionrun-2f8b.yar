rule TTP_XOR_QUAD_CurrentVersionRun_2f8b {
  strings:
    $key_2f8b = { 7c e4 [2] 58 ea [2] 73 c6 [2] 5d e4 [2] 49 ff [2] 46 e5 [2] 58 f8 [2] 5a f9 [2] 41 ff [2] 5d f8 [2] 41 d7 }

  condition:
    any of them
}