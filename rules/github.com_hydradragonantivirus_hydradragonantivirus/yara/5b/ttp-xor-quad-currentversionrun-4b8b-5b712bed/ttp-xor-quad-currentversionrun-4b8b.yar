rule TTP_XOR_QUAD_CurrentVersionRun_4b8b {
  strings:
    $key_4b8b = { 18 e4 [2] 3c ea [2] 17 c6 [2] 39 e4 [2] 2d ff [2] 22 e5 [2] 3c f8 [2] 3e f9 [2] 25 ff [2] 39 f8 [2] 25 d7 }

  condition:
    any of them
}