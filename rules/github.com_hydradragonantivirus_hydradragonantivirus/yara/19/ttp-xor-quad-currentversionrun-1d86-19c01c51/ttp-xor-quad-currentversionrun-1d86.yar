rule TTP_XOR_QUAD_CurrentVersionRun_1d86 {
  strings:
    $key_1d86 = { 4e e9 [2] 6a e7 [2] 41 cb [2] 6f e9 [2] 7b f2 [2] 74 e8 [2] 6a f5 [2] 68 f4 [2] 73 f2 [2] 6f f5 [2] 73 da }

  condition:
    any of them
}