rule TTP_XOR_QUAD_CurrentVersionRun_7c97 {
  strings:
    $key_7c97 = { 2f f8 [2] 0b f6 [2] 20 da [2] 0e f8 [2] 1a e3 [2] 15 f9 [2] 0b e4 [2] 09 e5 [2] 12 e3 [2] 0e e4 [2] 12 cb }

  condition:
    any of them
}