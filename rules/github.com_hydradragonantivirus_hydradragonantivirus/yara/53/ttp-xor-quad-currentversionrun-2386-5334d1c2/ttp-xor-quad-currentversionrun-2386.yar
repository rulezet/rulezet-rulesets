rule TTP_XOR_QUAD_CurrentVersionRun_2386 {
  strings:
    $key_2386 = { 70 e9 [2] 54 e7 [2] 7f cb [2] 51 e9 [2] 45 f2 [2] 4a e8 [2] 54 f5 [2] 56 f4 [2] 4d f2 [2] 51 f5 [2] 4d da }

  condition:
    any of them
}