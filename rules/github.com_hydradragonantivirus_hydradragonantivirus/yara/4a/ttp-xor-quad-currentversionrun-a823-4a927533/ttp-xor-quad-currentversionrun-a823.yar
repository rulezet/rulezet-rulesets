rule TTP_XOR_QUAD_CurrentVersionRun_a823 {
  strings:
    $key_a823 = { fb 4c [2] df 42 [2] f4 6e [2] da 4c [2] ce 57 [2] c1 4d [2] df 50 [2] dd 51 [2] c6 57 [2] da 50 [2] c6 7f }

  condition:
    any of them
}