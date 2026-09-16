rule TTP_XOR_QUAD_CurrentVersionRun_6986 {
  strings:
    $key_6986 = { 3a e9 [2] 1e e7 [2] 35 cb [2] 1b e9 [2] 0f f2 [2] 00 e8 [2] 1e f5 [2] 1c f4 [2] 07 f2 [2] 1b f5 [2] 07 da }

  condition:
    any of them
}