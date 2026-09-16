rule TTP_XOR_QUAD_CurrentVersionRun_a81e {
  strings:
    $key_a81e = { fb 71 [2] df 7f [2] f4 53 [2] da 71 [2] ce 6a [2] c1 70 [2] df 6d [2] dd 6c [2] c6 6a [2] da 6d [2] c6 42 }

  condition:
    any of them
}