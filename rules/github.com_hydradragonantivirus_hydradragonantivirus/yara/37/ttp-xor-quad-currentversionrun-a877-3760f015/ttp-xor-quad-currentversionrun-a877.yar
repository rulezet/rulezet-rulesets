rule TTP_XOR_QUAD_CurrentVersionRun_a877 {
  strings:
    $key_a877 = { fb 18 [2] df 16 [2] f4 3a [2] da 18 [2] ce 03 [2] c1 19 [2] df 04 [2] dd 05 [2] c6 03 [2] da 04 [2] c6 2b }

  condition:
    any of them
}