rule TTP_XOR_QUAD_CurrentVersionRun_2986 {
  strings:
    $key_2986 = { 7a e9 [2] 5e e7 [2] 75 cb [2] 5b e9 [2] 4f f2 [2] 40 e8 [2] 5e f5 [2] 5c f4 [2] 47 f2 [2] 5b f5 [2] 47 da }

  condition:
    any of them
}