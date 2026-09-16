rule TTP_XOR_QUAD_CurrentVersionRun_ada8 {
  strings:
    $key_ada8 = { fe c7 [2] da c9 [2] f1 e5 [2] df c7 [2] cb dc [2] c4 c6 [2] da db [2] d8 da [2] c3 dc [2] df db [2] c3 f4 }

  condition:
    any of them
}