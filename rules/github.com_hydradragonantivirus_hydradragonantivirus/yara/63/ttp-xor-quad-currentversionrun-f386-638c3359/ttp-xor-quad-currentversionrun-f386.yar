rule TTP_XOR_QUAD_CurrentVersionRun_f386 {
  strings:
    $key_f386 = { a0 e9 [2] 84 e7 [2] af cb [2] 81 e9 [2] 95 f2 [2] 9a e8 [2] 84 f5 [2] 86 f4 [2] 9d f2 [2] 81 f5 [2] 9d da }

  condition:
    any of them
}