rule TTP_XOR_QUAD_CurrentVersionRun_5485 {
  strings:
    $key_5485 = { 07 ea [2] 23 e4 [2] 08 c8 [2] 26 ea [2] 32 f1 [2] 3d eb [2] 23 f6 [2] 21 f7 [2] 3a f1 [2] 26 f6 [2] 3a d9 }

  condition:
    any of them
}