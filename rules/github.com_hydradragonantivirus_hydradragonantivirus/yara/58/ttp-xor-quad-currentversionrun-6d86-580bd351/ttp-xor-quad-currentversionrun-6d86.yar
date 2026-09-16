rule TTP_XOR_QUAD_CurrentVersionRun_6d86 {
  strings:
    $key_6d86 = { 3e e9 [2] 1a e7 [2] 31 cb [2] 1f e9 [2] 0b f2 [2] 04 e8 [2] 1a f5 [2] 18 f4 [2] 03 f2 [2] 1f f5 [2] 03 da }

  condition:
    any of them
}