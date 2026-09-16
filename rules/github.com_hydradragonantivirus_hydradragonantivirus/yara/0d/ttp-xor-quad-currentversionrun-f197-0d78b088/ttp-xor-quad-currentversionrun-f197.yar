rule TTP_XOR_QUAD_CurrentVersionRun_f197 {
  strings:
    $key_f197 = { a2 f8 [2] 86 f6 [2] ad da [2] 83 f8 [2] 97 e3 [2] 98 f9 [2] 86 e4 [2] 84 e5 [2] 9f e3 [2] 83 e4 [2] 9f cb }

  condition:
    any of them
}