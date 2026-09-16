rule TTP_XOR_QUAD_CurrentVersionRun_a80a {
  strings:
    $key_a80a = { fb 65 [2] df 6b [2] f4 47 [2] da 65 [2] ce 7e [2] c1 64 [2] df 79 [2] dd 78 [2] c6 7e [2] da 79 [2] c6 56 }

  condition:
    any of them
}