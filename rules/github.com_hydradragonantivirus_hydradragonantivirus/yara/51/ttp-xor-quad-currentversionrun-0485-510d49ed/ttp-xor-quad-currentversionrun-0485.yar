rule TTP_XOR_QUAD_CurrentVersionRun_0485 {
  strings:
    $key_0485 = { 57 ea [2] 73 e4 [2] 58 c8 [2] 76 ea [2] 62 f1 [2] 6d eb [2] 73 f6 [2] 71 f7 [2] 6a f1 [2] 76 f6 [2] 6a d9 }

  condition:
    any of them
}