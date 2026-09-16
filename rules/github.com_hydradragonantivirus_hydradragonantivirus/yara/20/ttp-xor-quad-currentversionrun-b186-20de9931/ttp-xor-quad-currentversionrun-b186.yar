rule TTP_XOR_QUAD_CurrentVersionRun_b186 {
  strings:
    $key_b186 = { e2 e9 [2] c6 e7 [2] ed cb [2] c3 e9 [2] d7 f2 [2] d8 e8 [2] c6 f5 [2] c4 f4 [2] df f2 [2] c3 f5 [2] df da }

  condition:
    any of them
}