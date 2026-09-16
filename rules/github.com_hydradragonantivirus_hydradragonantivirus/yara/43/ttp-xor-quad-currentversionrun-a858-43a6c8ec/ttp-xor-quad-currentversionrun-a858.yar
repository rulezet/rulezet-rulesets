rule TTP_XOR_QUAD_CurrentVersionRun_a858 {
  strings:
    $key_a858 = { fb 37 [2] df 39 [2] f4 15 [2] da 37 [2] ce 2c [2] c1 36 [2] df 2b [2] dd 2a [2] c6 2c [2] da 2b [2] c6 04 }

  condition:
    any of them
}