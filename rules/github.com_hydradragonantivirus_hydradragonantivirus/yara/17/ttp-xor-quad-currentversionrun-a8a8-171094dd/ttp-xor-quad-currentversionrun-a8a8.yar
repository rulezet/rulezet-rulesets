rule TTP_XOR_QUAD_CurrentVersionRun_a8a8 {
  strings:
    $key_a8a8 = { fb c7 [2] df c9 [2] f4 e5 [2] da c7 [2] ce dc [2] c1 c6 [2] df db [2] dd da [2] c6 dc [2] da db [2] c6 f4 }

  condition:
    any of them
}