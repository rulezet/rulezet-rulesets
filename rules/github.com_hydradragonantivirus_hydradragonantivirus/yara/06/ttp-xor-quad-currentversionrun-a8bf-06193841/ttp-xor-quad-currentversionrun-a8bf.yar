rule TTP_XOR_QUAD_CurrentVersionRun_a8bf {
  strings:
    $key_a8bf = { fb d0 [2] df de [2] f4 f2 [2] da d0 [2] ce cb [2] c1 d1 [2] df cc [2] dd cd [2] c6 cb [2] da cc [2] c6 e3 }

  condition:
    any of them
}