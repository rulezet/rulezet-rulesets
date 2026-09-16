rule TTP_XOR_QUAD_CurrentVersionRun_0697 {
  strings:
    $key_0697 = { 55 f8 [2] 71 f6 [2] 5a da [2] 74 f8 [2] 60 e3 [2] 6f f9 [2] 71 e4 [2] 73 e5 [2] 68 e3 [2] 74 e4 [2] 68 cb }

  condition:
    any of them
}