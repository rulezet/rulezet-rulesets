rule TTP_XOR_QUAD_CurrentVersionRun_5186 {
  strings:
    $key_5186 = { 02 e9 [2] 26 e7 [2] 0d cb [2] 23 e9 [2] 37 f2 [2] 38 e8 [2] 26 f5 [2] 24 f4 [2] 3f f2 [2] 23 f5 [2] 3f da }

  condition:
    any of them
}