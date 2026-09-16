rule TTP_XOR_QUAD_CurrentVersionRun_1986 {
  strings:
    $key_1986 = { 4a e9 [2] 6e e7 [2] 45 cb [2] 6b e9 [2] 7f f2 [2] 70 e8 [2] 6e f5 [2] 6c f4 [2] 77 f2 [2] 6b f5 [2] 77 da }

  condition:
    any of them
}