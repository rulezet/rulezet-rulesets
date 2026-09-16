rule TTP_XOR_QUAD_CurrentVersionRun_0186 {
  strings:
    $key_0186 = { 52 e9 [2] 76 e7 [2] 5d cb [2] 73 e9 [2] 67 f2 [2] 68 e8 [2] 76 f5 [2] 74 f4 [2] 6f f2 [2] 73 f5 [2] 6f da }

  condition:
    any of them
}