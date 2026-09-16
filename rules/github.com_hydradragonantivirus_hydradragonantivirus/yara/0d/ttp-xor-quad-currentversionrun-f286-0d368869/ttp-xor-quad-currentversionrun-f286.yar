rule TTP_XOR_QUAD_CurrentVersionRun_f286 {
  strings:
    $key_f286 = { a1 e9 [2] 85 e7 [2] ae cb [2] 80 e9 [2] 94 f2 [2] 9b e8 [2] 85 f5 [2] 87 f4 [2] 9c f2 [2] 80 f5 [2] 9c da }

  condition:
    any of them
}