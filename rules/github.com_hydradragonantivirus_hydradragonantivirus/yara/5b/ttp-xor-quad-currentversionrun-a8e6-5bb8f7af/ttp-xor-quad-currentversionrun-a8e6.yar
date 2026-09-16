rule TTP_XOR_QUAD_CurrentVersionRun_a8e6 {
  strings:
    $key_a8e6 = { fb 89 [2] df 87 [2] f4 ab [2] da 89 [2] ce 92 [2] c1 88 [2] df 95 [2] dd 94 [2] c6 92 [2] da 95 [2] c6 ba }

  condition:
    any of them
}