rule TTP_XOR_QUAD_CurrentVersionRun_a8b5 {
  strings:
    $key_a8b5 = { fb da [2] df d4 [2] f4 f8 [2] da da [2] ce c1 [2] c1 db [2] df c6 [2] dd c7 [2] c6 c1 [2] da c6 [2] c6 e9 }

  condition:
    any of them
}