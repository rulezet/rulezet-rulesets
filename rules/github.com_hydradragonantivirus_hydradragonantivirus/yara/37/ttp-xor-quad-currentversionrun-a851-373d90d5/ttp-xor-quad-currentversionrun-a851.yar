rule TTP_XOR_QUAD_CurrentVersionRun_a851 {
  strings:
    $key_a851 = { fb 3e [2] df 30 [2] f4 1c [2] da 3e [2] ce 25 [2] c1 3f [2] df 22 [2] dd 23 [2] c6 25 [2] da 22 [2] c6 0d }

  condition:
    any of them
}