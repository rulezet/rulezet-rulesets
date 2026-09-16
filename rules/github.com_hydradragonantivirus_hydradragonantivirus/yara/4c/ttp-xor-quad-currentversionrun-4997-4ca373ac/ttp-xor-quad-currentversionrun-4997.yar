rule TTP_XOR_QUAD_CurrentVersionRun_4997 {
  strings:
    $key_4997 = { 1a f8 [2] 3e f6 [2] 15 da [2] 3b f8 [2] 2f e3 [2] 20 f9 [2] 3e e4 [2] 3c e5 [2] 27 e3 [2] 3b e4 [2] 27 cb }

  condition:
    any of them
}