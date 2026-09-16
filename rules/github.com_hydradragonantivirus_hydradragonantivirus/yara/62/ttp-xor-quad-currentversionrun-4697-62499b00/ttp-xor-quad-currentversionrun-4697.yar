rule TTP_XOR_QUAD_CurrentVersionRun_4697 {
  strings:
    $key_4697 = { 15 f8 [2] 31 f6 [2] 1a da [2] 34 f8 [2] 20 e3 [2] 2f f9 [2] 31 e4 [2] 33 e5 [2] 28 e3 [2] 34 e4 [2] 28 cb }

  condition:
    any of them
}