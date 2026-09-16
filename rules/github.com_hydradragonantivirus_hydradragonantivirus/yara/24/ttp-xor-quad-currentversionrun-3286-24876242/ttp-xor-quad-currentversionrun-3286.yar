rule TTP_XOR_QUAD_CurrentVersionRun_3286 {
  strings:
    $key_3286 = { 61 e9 [2] 45 e7 [2] 6e cb [2] 40 e9 [2] 54 f2 [2] 5b e8 [2] 45 f5 [2] 47 f4 [2] 5c f2 [2] 40 f5 [2] 5c da }

  condition:
    any of them
}