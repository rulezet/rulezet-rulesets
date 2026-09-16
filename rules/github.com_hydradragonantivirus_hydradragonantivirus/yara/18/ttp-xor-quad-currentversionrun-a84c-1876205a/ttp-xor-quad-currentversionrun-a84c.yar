rule TTP_XOR_QUAD_CurrentVersionRun_a84c {
  strings:
    $key_a84c = { fb 23 [2] df 2d [2] f4 01 [2] da 23 [2] ce 38 [2] c1 22 [2] df 3f [2] dd 3e [2] c6 38 [2] da 3f [2] c6 10 }

  condition:
    any of them
}