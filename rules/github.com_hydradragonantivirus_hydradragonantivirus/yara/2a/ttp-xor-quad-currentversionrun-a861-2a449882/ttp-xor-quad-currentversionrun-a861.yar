rule TTP_XOR_QUAD_CurrentVersionRun_a861 {
  strings:
    $key_a861 = { fb 0e [2] df 00 [2] f4 2c [2] da 0e [2] ce 15 [2] c1 0f [2] df 12 [2] dd 13 [2] c6 15 [2] da 12 [2] c6 3d }

  condition:
    any of them
}