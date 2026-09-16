rule TTP_XOR_QUAD_CurrentVersionRun_fc86 {
  strings:
    $key_fc86 = { af e9 [2] 8b e7 [2] a0 cb [2] 8e e9 [2] 9a f2 [2] 95 e8 [2] 8b f5 [2] 89 f4 [2] 92 f2 [2] 8e f5 [2] 92 da }

  condition:
    any of them
}