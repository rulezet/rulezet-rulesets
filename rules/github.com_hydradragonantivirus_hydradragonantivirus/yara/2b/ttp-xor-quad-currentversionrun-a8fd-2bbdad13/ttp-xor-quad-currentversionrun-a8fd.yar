rule TTP_XOR_QUAD_CurrentVersionRun_a8fd {
  strings:
    $key_a8fd = { fb 92 [2] df 9c [2] f4 b0 [2] da 92 [2] ce 89 [2] c1 93 [2] df 8e [2] dd 8f [2] c6 89 [2] da 8e [2] c6 a1 }

  condition:
    any of them
}