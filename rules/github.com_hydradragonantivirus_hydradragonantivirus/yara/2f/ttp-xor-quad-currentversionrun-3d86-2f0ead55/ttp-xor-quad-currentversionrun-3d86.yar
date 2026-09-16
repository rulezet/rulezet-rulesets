rule TTP_XOR_QUAD_CurrentVersionRun_3d86 {
  strings:
    $key_3d86 = { 6e e9 [2] 4a e7 [2] 61 cb [2] 4f e9 [2] 5b f2 [2] 54 e8 [2] 4a f5 [2] 48 f4 [2] 53 f2 [2] 4f f5 [2] 53 da }

  condition:
    any of them
}