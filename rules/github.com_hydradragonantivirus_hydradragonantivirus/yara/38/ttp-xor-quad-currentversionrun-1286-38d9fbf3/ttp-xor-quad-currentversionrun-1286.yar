rule TTP_XOR_QUAD_CurrentVersionRun_1286 {
  strings:
    $key_1286 = { 41 e9 [2] 65 e7 [2] 4e cb [2] 60 e9 [2] 74 f2 [2] 7b e8 [2] 65 f5 [2] 67 f4 [2] 7c f2 [2] 60 f5 [2] 7c da }

  condition:
    any of them
}