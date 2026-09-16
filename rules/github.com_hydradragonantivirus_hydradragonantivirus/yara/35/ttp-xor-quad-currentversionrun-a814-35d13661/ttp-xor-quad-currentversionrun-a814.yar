rule TTP_XOR_QUAD_CurrentVersionRun_a814 {
  strings:
    $key_a814 = { fb 7b [2] df 75 [2] f4 59 [2] da 7b [2] ce 60 [2] c1 7a [2] df 67 [2] dd 66 [2] c6 60 [2] da 67 [2] c6 48 }

  condition:
    any of them
}