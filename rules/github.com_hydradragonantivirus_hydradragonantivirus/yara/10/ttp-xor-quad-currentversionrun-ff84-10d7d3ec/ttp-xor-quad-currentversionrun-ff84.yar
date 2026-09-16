rule TTP_XOR_QUAD_CurrentVersionRun_ff84 {
  strings:
    $key_ff84 = { ac eb [2] 88 e5 [2] a3 c9 [2] 8d eb [2] 99 f0 [2] 96 ea [2] 88 f7 [2] 8a f6 [2] 91 f0 [2] 8d f7 [2] 91 d8 }

  condition:
    any of them
}