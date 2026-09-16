rule TTP_XOR_QUAD_CurrentVersionRun_5385 {
  strings:
    $key_5385 = { 00 ea [2] 24 e4 [2] 0f c8 [2] 21 ea [2] 35 f1 [2] 3a eb [2] 24 f6 [2] 26 f7 [2] 3d f1 [2] 21 f6 [2] 3d d9 }

  condition:
    any of them
}