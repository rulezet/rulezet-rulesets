rule TTP_XOR_QUAD_CurrentVersionRun_a874 {
  strings:
    $key_a874 = { fb 1b [2] df 15 [2] f4 39 [2] da 1b [2] ce 00 [2] c1 1a [2] df 07 [2] dd 06 [2] c6 00 [2] da 07 [2] c6 28 }

  condition:
    any of them
}