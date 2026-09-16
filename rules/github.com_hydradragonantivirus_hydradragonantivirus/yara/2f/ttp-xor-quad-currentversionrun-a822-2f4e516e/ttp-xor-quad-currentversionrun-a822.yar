rule TTP_XOR_QUAD_CurrentVersionRun_a822 {
  strings:
    $key_a822 = { fb 4d [2] df 43 [2] f4 6f [2] da 4d [2] ce 56 [2] c1 4c [2] df 51 [2] dd 50 [2] c6 56 [2] da 51 [2] c6 7e }

  condition:
    any of them
}