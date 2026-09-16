rule TTP_XOR_QUAD_CurrentVersionRun_0086 {
  strings:
    $key_0086 = { 53 e9 [2] 77 e7 [2] 5c cb [2] 72 e9 [2] 66 f2 [2] 69 e8 [2] 77 f5 [2] 75 f4 [2] 6e f2 [2] 72 f5 [2] 6e da }

  condition:
    any of them
}