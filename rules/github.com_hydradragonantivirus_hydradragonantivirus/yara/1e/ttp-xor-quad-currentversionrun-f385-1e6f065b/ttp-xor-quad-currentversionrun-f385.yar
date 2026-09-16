rule TTP_XOR_QUAD_CurrentVersionRun_f385 {
  strings:
    $key_f385 = { a0 ea [2] 84 e4 [2] af c8 [2] 81 ea [2] 95 f1 [2] 9a eb [2] 84 f6 [2] 86 f7 [2] 9d f1 [2] 81 f6 [2] 9d d9 }

  condition:
    any of them
}