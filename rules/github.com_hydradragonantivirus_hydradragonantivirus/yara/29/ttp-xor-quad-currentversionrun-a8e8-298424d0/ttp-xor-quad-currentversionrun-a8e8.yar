rule TTP_XOR_QUAD_CurrentVersionRun_a8e8 {
  strings:
    $key_a8e8 = { fb 87 [2] df 89 [2] f4 a5 [2] da 87 [2] ce 9c [2] c1 86 [2] df 9b [2] dd 9a [2] c6 9c [2] da 9b [2] c6 b4 }

  condition:
    any of them
}