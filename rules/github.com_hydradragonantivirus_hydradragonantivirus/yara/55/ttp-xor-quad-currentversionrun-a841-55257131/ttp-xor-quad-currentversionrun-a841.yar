rule TTP_XOR_QUAD_CurrentVersionRun_a841 {
  strings:
    $key_a841 = { fb 2e [2] df 20 [2] f4 0c [2] da 2e [2] ce 35 [2] c1 2f [2] df 32 [2] dd 33 [2] c6 35 [2] da 32 [2] c6 1d }

  condition:
    any of them
}