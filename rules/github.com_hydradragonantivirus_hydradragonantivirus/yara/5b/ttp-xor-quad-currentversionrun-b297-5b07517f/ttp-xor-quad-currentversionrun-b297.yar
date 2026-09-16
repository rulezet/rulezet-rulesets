rule TTP_XOR_QUAD_CurrentVersionRun_b297 {
  strings:
    $key_b297 = { e1 f8 [2] c5 f6 [2] ee da [2] c0 f8 [2] d4 e3 [2] db f9 [2] c5 e4 [2] c7 e5 [2] dc e3 [2] c0 e4 [2] dc cb }

  condition:
    any of them
}