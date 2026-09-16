rule TTP_XOR_QUAD_CurrentVersionRun_f384 {
  strings:
    $key_f384 = { a0 eb [2] 84 e5 [2] af c9 [2] 81 eb [2] 95 f0 [2] 9a ea [2] 84 f7 [2] 86 f6 [2] 9d f0 [2] 81 f7 [2] 9d d8 }

  condition:
    any of them
}