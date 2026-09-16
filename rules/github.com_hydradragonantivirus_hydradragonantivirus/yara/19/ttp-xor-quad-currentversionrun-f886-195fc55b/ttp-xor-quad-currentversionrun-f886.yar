rule TTP_XOR_QUAD_CurrentVersionRun_f886 {
  strings:
    $key_f886 = { ab e9 [2] 8f e7 [2] a4 cb [2] 8a e9 [2] 9e f2 [2] 91 e8 [2] 8f f5 [2] 8d f4 [2] 96 f2 [2] 8a f5 [2] 96 da }

  condition:
    any of them
}