rule TTP_XOR_QUAD_CurrentVersionRun_0997 {
  strings:
    $key_0997 = { 5a f8 [2] 7e f6 [2] 55 da [2] 7b f8 [2] 6f e3 [2] 60 f9 [2] 7e e4 [2] 7c e5 [2] 67 e3 [2] 7b e4 [2] 67 cb }

  condition:
    any of them
}