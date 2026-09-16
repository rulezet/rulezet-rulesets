rule TTP_XOR_QUAD_CurrentVersionRun_a838 {
  strings:
    $key_a838 = { fb 57 [2] df 59 [2] f4 75 [2] da 57 [2] ce 4c [2] c1 56 [2] df 4b [2] dd 4a [2] c6 4c [2] da 4b [2] c6 64 }

  condition:
    any of them
}