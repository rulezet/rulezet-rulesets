rule TTP_XOR_QUAD_CurrentVersionRun_a864 {
  strings:
    $key_a864 = { fb 0b [2] df 05 [2] f4 29 [2] da 0b [2] ce 10 [2] c1 0a [2] df 17 [2] dd 16 [2] c6 10 [2] da 17 [2] c6 38 }

  condition:
    any of them
}