rule TTP_XOR_QUAD_CurrentVersionRun_a868 {
  strings:
    $key_a868 = { fb 07 [2] df 09 [2] f4 25 [2] da 07 [2] ce 1c [2] c1 06 [2] df 1b [2] dd 1a [2] c6 1c [2] da 1b [2] c6 34 }

  condition:
    any of them
}