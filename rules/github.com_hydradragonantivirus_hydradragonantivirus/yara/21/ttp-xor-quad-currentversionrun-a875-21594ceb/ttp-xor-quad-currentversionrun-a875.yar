rule TTP_XOR_QUAD_CurrentVersionRun_a875 {
  strings:
    $key_a875 = { fb 1a [2] df 14 [2] f4 38 [2] da 1a [2] ce 01 [2] c1 1b [2] df 06 [2] dd 07 [2] c6 01 [2] da 06 [2] c6 29 }

  condition:
    any of them
}