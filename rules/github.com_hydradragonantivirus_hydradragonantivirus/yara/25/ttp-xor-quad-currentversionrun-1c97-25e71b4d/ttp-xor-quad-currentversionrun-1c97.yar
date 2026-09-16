rule TTP_XOR_QUAD_CurrentVersionRun_1c97 {
  strings:
    $key_1c97 = { 4f f8 [2] 6b f6 [2] 40 da [2] 6e f8 [2] 7a e3 [2] 75 f9 [2] 6b e4 [2] 69 e5 [2] 72 e3 [2] 6e e4 [2] 72 cb }

  condition:
    any of them
}