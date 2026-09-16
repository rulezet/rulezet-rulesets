rule TTP_XOR_QUAD_CurrentVersionRun_4986 {
  strings:
    $key_4986 = { 1a e9 [2] 3e e7 [2] 15 cb [2] 3b e9 [2] 2f f2 [2] 20 e8 [2] 3e f5 [2] 3c f4 [2] 27 f2 [2] 3b f5 [2] 27 da }

  condition:
    any of them
}