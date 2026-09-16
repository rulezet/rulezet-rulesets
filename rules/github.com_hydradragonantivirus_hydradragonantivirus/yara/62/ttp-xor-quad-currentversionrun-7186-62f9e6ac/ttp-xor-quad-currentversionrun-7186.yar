rule TTP_XOR_QUAD_CurrentVersionRun_7186 {
  strings:
    $key_7186 = { 22 e9 [2] 06 e7 [2] 2d cb [2] 03 e9 [2] 17 f2 [2] 18 e8 [2] 06 f5 [2] 04 f4 [2] 1f f2 [2] 03 f5 [2] 1f da }

  condition:
    any of them
}