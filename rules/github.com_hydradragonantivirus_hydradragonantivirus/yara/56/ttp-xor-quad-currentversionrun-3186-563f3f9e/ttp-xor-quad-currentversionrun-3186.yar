rule TTP_XOR_QUAD_CurrentVersionRun_3186 {
  strings:
    $key_3186 = { 62 e9 [2] 46 e7 [2] 6d cb [2] 43 e9 [2] 57 f2 [2] 58 e8 [2] 46 f5 [2] 44 f4 [2] 5f f2 [2] 43 f5 [2] 5f da }

  condition:
    any of them
}