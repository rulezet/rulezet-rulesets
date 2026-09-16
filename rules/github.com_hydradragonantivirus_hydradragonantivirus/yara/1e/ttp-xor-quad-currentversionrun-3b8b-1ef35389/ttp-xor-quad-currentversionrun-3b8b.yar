rule TTP_XOR_QUAD_CurrentVersionRun_3b8b {
  strings:
    $key_3b8b = { 68 e4 [2] 4c ea [2] 67 c6 [2] 49 e4 [2] 5d ff [2] 52 e5 [2] 4c f8 [2] 4e f9 [2] 55 ff [2] 49 f8 [2] 55 d7 }

  condition:
    any of them
}