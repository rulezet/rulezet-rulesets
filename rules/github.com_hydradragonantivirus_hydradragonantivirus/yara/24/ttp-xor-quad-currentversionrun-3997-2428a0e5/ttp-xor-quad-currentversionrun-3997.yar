rule TTP_XOR_QUAD_CurrentVersionRun_3997 {
  strings:
    $key_3997 = { 6a f8 [2] 4e f6 [2] 65 da [2] 4b f8 [2] 5f e3 [2] 50 f9 [2] 4e e4 [2] 4c e5 [2] 57 e3 [2] 4b e4 [2] 57 cb }

  condition:
    any of them
}