rule TTP_XOR_QUAD_CurrentVersionRun_1197 {
  strings:
    $key_1197 = { 42 f8 [2] 66 f6 [2] 4d da [2] 63 f8 [2] 77 e3 [2] 78 f9 [2] 66 e4 [2] 64 e5 [2] 7f e3 [2] 63 e4 [2] 7f cb }

  condition:
    any of them
}