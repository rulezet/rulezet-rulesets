rule TTP_XOR_QUAD_CurrentVersionRun_a84a {
  strings:
    $key_a84a = { fb 25 [2] df 2b [2] f4 07 [2] da 25 [2] ce 3e [2] c1 24 [2] df 39 [2] dd 38 [2] c6 3e [2] da 39 [2] c6 16 }

  condition:
    any of them
}