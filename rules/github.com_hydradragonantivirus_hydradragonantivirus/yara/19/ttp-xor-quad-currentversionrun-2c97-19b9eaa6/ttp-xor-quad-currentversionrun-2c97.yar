rule TTP_XOR_QUAD_CurrentVersionRun_2c97 {
  strings:
    $key_2c97 = { 7f f8 [2] 5b f6 [2] 70 da [2] 5e f8 [2] 4a e3 [2] 45 f9 [2] 5b e4 [2] 59 e5 [2] 42 e3 [2] 5e e4 [2] 42 cb }

  condition:
    any of them
}