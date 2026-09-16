rule TTP_XOR_QUAD_CurrentVersionRun_2197 {
  strings:
    $key_2197 = { 72 f8 [2] 56 f6 [2] 7d da [2] 53 f8 [2] 47 e3 [2] 48 f9 [2] 56 e4 [2] 54 e5 [2] 4f e3 [2] 53 e4 [2] 4f cb }

  condition:
    any of them
}