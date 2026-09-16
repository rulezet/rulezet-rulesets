rule TTP_XOR_QUAD_CurrentVersionRun_b1b3 {
  strings:
    $key_b1b3 = { e2 dc [2] c6 d2 [2] ed fe [2] c3 dc [2] d7 c7 [2] d8 dd [2] c6 c0 [2] c4 c1 [2] df c7 [2] c3 c0 [2] df ef }

  condition:
    any of them
}