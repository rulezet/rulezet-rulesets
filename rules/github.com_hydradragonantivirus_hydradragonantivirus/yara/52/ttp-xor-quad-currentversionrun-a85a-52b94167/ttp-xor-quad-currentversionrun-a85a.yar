rule TTP_XOR_QUAD_CurrentVersionRun_a85a {
  strings:
    $key_a85a = { fb 35 [2] df 3b [2] f4 17 [2] da 35 [2] ce 2e [2] c1 34 [2] df 29 [2] dd 28 [2] c6 2e [2] da 29 [2] c6 06 }

  condition:
    any of them
}