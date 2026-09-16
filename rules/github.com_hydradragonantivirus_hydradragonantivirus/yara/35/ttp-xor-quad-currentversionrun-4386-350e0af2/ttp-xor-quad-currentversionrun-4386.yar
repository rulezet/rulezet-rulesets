rule TTP_XOR_QUAD_CurrentVersionRun_4386 {
  strings:
    $key_4386 = { 10 e9 [2] 34 e7 [2] 1f cb [2] 31 e9 [2] 25 f2 [2] 2a e8 [2] 34 f5 [2] 36 f4 [2] 2d f2 [2] 31 f5 [2] 2d da }

  condition:
    any of them
}