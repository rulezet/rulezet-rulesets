rule TTP_XOR_QUAD_CurrentVersionRun_5197 {
  strings:
    $key_5197 = { 02 f8 [2] 26 f6 [2] 0d da [2] 23 f8 [2] 37 e3 [2] 38 f9 [2] 26 e4 [2] 24 e5 [2] 3f e3 [2] 23 e4 [2] 3f cb }

  condition:
    any of them
}