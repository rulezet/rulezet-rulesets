rule TTP_XOR_QUAD_CurrentVersionRun_a844 {
  strings:
    $key_a844 = { fb 2b [2] df 25 [2] f4 09 [2] da 2b [2] ce 30 [2] c1 2a [2] df 37 [2] dd 36 [2] c6 30 [2] da 37 [2] c6 18 }

  condition:
    any of them
}