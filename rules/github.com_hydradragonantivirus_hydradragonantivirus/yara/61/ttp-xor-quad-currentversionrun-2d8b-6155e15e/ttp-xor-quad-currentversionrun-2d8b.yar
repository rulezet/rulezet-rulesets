rule TTP_XOR_QUAD_CurrentVersionRun_2d8b {
  strings:
    $key_2d8b = { 7e e4 [2] 5a ea [2] 71 c6 [2] 5f e4 [2] 4b ff [2] 44 e5 [2] 5a f8 [2] 58 f9 [2] 43 ff [2] 5f f8 [2] 43 d7 }

  condition:
    any of them
}