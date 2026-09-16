rule TTP_XOR_QUAD_CurrentVersionRun_a8b9 {
  strings:
    $key_a8b9 = { fb d6 [2] df d8 [2] f4 f4 [2] da d6 [2] ce cd [2] c1 d7 [2] df ca [2] dd cb [2] c6 cd [2] da ca [2] c6 e5 }

  condition:
    any of them
}