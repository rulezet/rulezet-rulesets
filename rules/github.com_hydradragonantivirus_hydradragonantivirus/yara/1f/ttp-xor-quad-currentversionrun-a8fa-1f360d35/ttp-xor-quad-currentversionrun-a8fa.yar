rule TTP_XOR_QUAD_CurrentVersionRun_a8fa {
  strings:
    $key_a8fa = { fb 95 [2] df 9b [2] f4 b7 [2] da 95 [2] ce 8e [2] c1 94 [2] df 89 [2] dd 88 [2] c6 8e [2] da 89 [2] c6 a6 }

  condition:
    any of them
}