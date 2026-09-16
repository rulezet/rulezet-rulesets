rule TTP_XOR_QUAD_CurrentVersionRun_e485 {
  strings:
    $key_e485 = { b7 ea [2] 93 e4 [2] b8 c8 [2] 96 ea [2] 82 f1 [2] 8d eb [2] 93 f6 [2] 91 f7 [2] 8a f1 [2] 96 f6 [2] 8a d9 }

  condition:
    any of them
}