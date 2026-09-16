rule TTP_XOR_QUAD_CurrentVersionRun_6997 {
  strings:
    $key_6997 = { 3a f8 [2] 1e f6 [2] 35 da [2] 1b f8 [2] 0f e3 [2] 00 f9 [2] 1e e4 [2] 1c e5 [2] 07 e3 [2] 1b e4 [2] 07 cb }

  condition:
    any of them
}