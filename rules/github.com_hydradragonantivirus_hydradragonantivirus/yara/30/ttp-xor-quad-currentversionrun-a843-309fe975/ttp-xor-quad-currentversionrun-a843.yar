rule TTP_XOR_QUAD_CurrentVersionRun_a843 {
  strings:
    $key_a843 = { fb 2c [2] df 22 [2] f4 0e [2] da 2c [2] ce 37 [2] c1 2d [2] df 30 [2] dd 31 [2] c6 37 [2] da 30 [2] c6 1f }

  condition:
    any of them
}