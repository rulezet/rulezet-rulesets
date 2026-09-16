rule TTP_XOR_QUAD_CurrentVersionRun_0197 {
  strings:
    $key_0197 = { 52 f8 [2] 76 f6 [2] 5d da [2] 73 f8 [2] 67 e3 [2] 68 f9 [2] 76 e4 [2] 74 e5 [2] 6f e3 [2] 73 e4 [2] 6f cb }

  condition:
    any of them
}