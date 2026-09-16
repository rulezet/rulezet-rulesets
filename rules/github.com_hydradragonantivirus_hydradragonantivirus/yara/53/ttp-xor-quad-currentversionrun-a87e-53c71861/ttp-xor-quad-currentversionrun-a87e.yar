rule TTP_XOR_QUAD_CurrentVersionRun_a87e {
  strings:
    $key_a87e = { fb 11 [2] df 1f [2] f4 33 [2] da 11 [2] ce 0a [2] c1 10 [2] df 0d [2] dd 0c [2] c6 0a [2] da 0d [2] c6 22 }

  condition:
    any of them
}