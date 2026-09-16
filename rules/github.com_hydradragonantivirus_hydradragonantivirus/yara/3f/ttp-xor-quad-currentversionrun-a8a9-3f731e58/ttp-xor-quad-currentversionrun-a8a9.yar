rule TTP_XOR_QUAD_CurrentVersionRun_a8a9 {
  strings:
    $key_a8a9 = { fb c6 [2] df c8 [2] f4 e4 [2] da c6 [2] ce dd [2] c1 c7 [2] df da [2] dd db [2] c6 dd [2] da da [2] c6 f5 }

  condition:
    any of them
}