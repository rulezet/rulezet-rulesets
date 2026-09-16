rule TTP_XOR_QUAD_CurrentVersionRun_0286 {
  strings:
    $key_0286 = { 51 e9 [2] 75 e7 [2] 5e cb [2] 70 e9 [2] 64 f2 [2] 6b e8 [2] 75 f5 [2] 77 f4 [2] 6c f2 [2] 70 f5 [2] 6c da }

  condition:
    any of them
}