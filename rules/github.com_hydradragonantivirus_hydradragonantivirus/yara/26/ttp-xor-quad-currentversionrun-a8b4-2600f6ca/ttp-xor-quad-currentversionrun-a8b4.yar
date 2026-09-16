rule TTP_XOR_QUAD_CurrentVersionRun_a8b4 {
  strings:
    $key_a8b4 = { fb db [2] df d5 [2] f4 f9 [2] da db [2] ce c0 [2] c1 da [2] df c7 [2] dd c6 [2] c6 c0 [2] da c7 [2] c6 e8 }

  condition:
    any of them
}