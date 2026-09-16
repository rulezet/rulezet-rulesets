rule TTP_XOR_QUAD_CurrentVersionRun_a842 {
  strings:
    $key_a842 = { fb 2d [2] df 23 [2] f4 0f [2] da 2d [2] ce 36 [2] c1 2c [2] df 31 [2] dd 30 [2] c6 36 [2] da 31 [2] c6 1e }

  condition:
    any of them
}