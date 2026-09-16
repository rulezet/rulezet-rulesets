rule TTP_XOR_QUAD_CurrentVersionRun_a8f5 {
  strings:
    $key_a8f5 = { fb 9a [2] df 94 [2] f4 b8 [2] da 9a [2] ce 81 [2] c1 9b [2] df 86 [2] dd 87 [2] c6 81 [2] da 86 [2] c6 a9 }

  condition:
    any of them
}