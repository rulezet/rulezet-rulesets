rule TTP_XOR_QUAD_CurrentVersionRun_a8b6 {
  strings:
    $key_a8b6 = { fb d9 [2] df d7 [2] f4 fb [2] da d9 [2] ce c2 [2] c1 d8 [2] df c5 [2] dd c4 [2] c6 c2 [2] da c5 [2] c6 ea }

  condition:
    any of them
}