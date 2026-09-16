rule TTP_XOR_QUAD_CurrentVersionRun_a859 {
  strings:
    $key_a859 = { fb 36 [2] df 38 [2] f4 14 [2] da 36 [2] ce 2d [2] c1 37 [2] df 2a [2] dd 2b [2] c6 2d [2] da 2a [2] c6 05 }

  condition:
    any of them
}