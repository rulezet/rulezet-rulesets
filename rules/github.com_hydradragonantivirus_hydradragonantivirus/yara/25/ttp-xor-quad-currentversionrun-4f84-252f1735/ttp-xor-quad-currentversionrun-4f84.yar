rule TTP_XOR_QUAD_CurrentVersionRun_4f84 {
  strings:
    $key_4f84 = { 1c eb [2] 38 e5 [2] 13 c9 [2] 3d eb [2] 29 f0 [2] 26 ea [2] 38 f7 [2] 3a f6 [2] 21 f0 [2] 3d f7 [2] 21 d8 }

  condition:
    any of them
}