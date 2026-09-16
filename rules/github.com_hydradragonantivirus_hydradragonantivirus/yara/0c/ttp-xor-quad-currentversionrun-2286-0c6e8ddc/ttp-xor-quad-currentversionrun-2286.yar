rule TTP_XOR_QUAD_CurrentVersionRun_2286 {
  strings:
    $key_2286 = { 71 e9 [2] 55 e7 [2] 7e cb [2] 50 e9 [2] 44 f2 [2] 4b e8 [2] 55 f5 [2] 57 f4 [2] 4c f2 [2] 50 f5 [2] 4c da }

  condition:
    any of them
}