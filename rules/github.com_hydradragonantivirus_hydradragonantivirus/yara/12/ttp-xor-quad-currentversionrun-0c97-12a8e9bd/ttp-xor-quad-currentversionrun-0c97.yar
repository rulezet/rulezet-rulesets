rule TTP_XOR_QUAD_CurrentVersionRun_0c97 {
  strings:
    $key_0c97 = { 5f f8 [2] 7b f6 [2] 50 da [2] 7e f8 [2] 6a e3 [2] 65 f9 [2] 7b e4 [2] 79 e5 [2] 62 e3 [2] 7e e4 [2] 62 cb }

  condition:
    any of them
}