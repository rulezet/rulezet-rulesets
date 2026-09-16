rule TTP_XOR_QUAD_CurrentVersionRun_e997 {
  strings:
    $key_e997 = { ba f8 [2] 9e f6 [2] b5 da [2] 9b f8 [2] 8f e3 [2] 80 f9 [2] 9e e4 [2] 9c e5 [2] 87 e3 [2] 9b e4 [2] 87 cb }

  condition:
    any of them
}