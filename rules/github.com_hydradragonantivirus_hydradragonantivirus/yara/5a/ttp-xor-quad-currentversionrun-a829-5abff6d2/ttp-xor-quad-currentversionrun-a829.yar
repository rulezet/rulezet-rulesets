rule TTP_XOR_QUAD_CurrentVersionRun_a829 {
  strings:
    $key_a829 = { fb 46 [2] df 48 [2] f4 64 [2] da 46 [2] ce 5d [2] c1 47 [2] df 5a [2] dd 5b [2] c6 5d [2] da 5a [2] c6 75 }

  condition:
    any of them
}