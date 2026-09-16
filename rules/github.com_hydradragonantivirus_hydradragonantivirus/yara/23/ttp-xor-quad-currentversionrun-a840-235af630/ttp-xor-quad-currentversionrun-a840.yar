rule TTP_XOR_QUAD_CurrentVersionRun_a840 {
  strings:
    $key_a840 = { fb 2f [2] df 21 [2] f4 0d [2] da 2f [2] ce 34 [2] c1 2e [2] df 33 [2] dd 32 [2] c6 34 [2] da 33 [2] c6 1c }

  condition:
    any of them
}