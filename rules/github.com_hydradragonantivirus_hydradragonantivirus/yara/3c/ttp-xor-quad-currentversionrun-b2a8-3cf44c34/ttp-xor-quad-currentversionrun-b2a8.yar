rule TTP_XOR_QUAD_CurrentVersionRun_b2a8 {
  strings:
    $key_b2a8 = { e1 c7 [2] c5 c9 [2] ee e5 [2] c0 c7 [2] d4 dc [2] db c6 [2] c5 db [2] c7 da [2] dc dc [2] c0 db [2] dc f4 }

  condition:
    any of them
}