rule TTP_XOR_QUAD_CurrentVersionRun_e884 {
  strings:
    $key_e884 = { bb eb [2] 9f e5 [2] b4 c9 [2] 9a eb [2] 8e f0 [2] 81 ea [2] 9f f7 [2] 9d f6 [2] 86 f0 [2] 9a f7 [2] 86 d8 }

  condition:
    any of them
}