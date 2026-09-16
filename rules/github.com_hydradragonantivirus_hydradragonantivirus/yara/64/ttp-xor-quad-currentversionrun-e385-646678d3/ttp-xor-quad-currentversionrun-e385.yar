rule TTP_XOR_QUAD_CurrentVersionRun_e385 {
  strings:
    $key_e385 = { b0 ea [2] 94 e4 [2] bf c8 [2] 91 ea [2] 85 f1 [2] 8a eb [2] 94 f6 [2] 96 f7 [2] 8d f1 [2] 91 f6 [2] 8d d9 }

  condition:
    any of them
}