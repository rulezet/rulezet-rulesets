rule TTP_XOR_QUAD_CurrentVersionRun_4485 {
  strings:
    $key_4485 = { 17 ea [2] 33 e4 [2] 18 c8 [2] 36 ea [2] 22 f1 [2] 2d eb [2] 33 f6 [2] 31 f7 [2] 2a f1 [2] 36 f6 [2] 2a d9 }

  condition:
    any of them
}