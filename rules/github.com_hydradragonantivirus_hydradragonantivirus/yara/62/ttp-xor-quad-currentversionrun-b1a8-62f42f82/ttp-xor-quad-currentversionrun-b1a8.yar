rule TTP_XOR_QUAD_CurrentVersionRun_b1a8 {
  strings:
    $key_b1a8 = { e2 c7 [2] c6 c9 [2] ed e5 [2] c3 c7 [2] d7 dc [2] d8 c6 [2] c6 db [2] c4 da [2] df dc [2] c3 db [2] df f4 }

  condition:
    any of them
}