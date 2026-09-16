rule TTP_XOR_QUAD_CurrentVersionRun_a836 {
  strings:
    $key_a836 = { fb 59 [2] df 57 [2] f4 7b [2] da 59 [2] ce 42 [2] c1 58 [2] df 45 [2] dd 44 [2] c6 42 [2] da 45 [2] c6 6a }

  condition:
    any of them
}