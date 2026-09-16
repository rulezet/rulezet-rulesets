rule TTP_XOR_QUAD_CurrentVersionRun_a8ba {
  strings:
    $key_a8ba = { fb d5 [2] df db [2] f4 f7 [2] da d5 [2] ce ce [2] c1 d4 [2] df c9 [2] dd c8 [2] c6 ce [2] da c9 [2] c6 e6 }

  condition:
    any of them
}