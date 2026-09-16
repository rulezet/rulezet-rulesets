rule TTP_XOR_QUAD_CurrentVersionRun_a8f3 {
  strings:
    $key_a8f3 = { fb 9c [2] df 92 [2] f4 be [2] da 9c [2] ce 87 [2] c1 9d [2] df 80 [2] dd 81 [2] c6 87 [2] da 80 [2] c6 af }

  condition:
    any of them
}