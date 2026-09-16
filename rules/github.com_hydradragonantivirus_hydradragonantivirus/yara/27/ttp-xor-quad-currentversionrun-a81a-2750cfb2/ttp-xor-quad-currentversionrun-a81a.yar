rule TTP_XOR_QUAD_CurrentVersionRun_a81a {
  strings:
    $key_a81a = { fb 75 [2] df 7b [2] f4 57 [2] da 75 [2] ce 6e [2] c1 74 [2] df 69 [2] dd 68 [2] c6 6e [2] da 69 [2] c6 46 }

  condition:
    any of them
}