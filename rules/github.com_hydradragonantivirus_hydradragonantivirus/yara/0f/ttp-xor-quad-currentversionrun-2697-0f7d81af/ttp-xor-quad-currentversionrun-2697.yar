rule TTP_XOR_QUAD_CurrentVersionRun_2697 {
  strings:
    $key_2697 = { 75 f8 [2] 51 f6 [2] 7a da [2] 54 f8 [2] 40 e3 [2] 4f f9 [2] 51 e4 [2] 53 e5 [2] 48 e3 [2] 54 e4 [2] 48 cb }

  condition:
    any of them
}