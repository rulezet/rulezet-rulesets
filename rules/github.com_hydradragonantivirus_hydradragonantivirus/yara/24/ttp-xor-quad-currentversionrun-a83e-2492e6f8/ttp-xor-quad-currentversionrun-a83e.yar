rule TTP_XOR_QUAD_CurrentVersionRun_a83e {
  strings:
    $key_a83e = { fb 51 [2] df 5f [2] f4 73 [2] da 51 [2] ce 4a [2] c1 50 [2] df 4d [2] dd 4c [2] c6 4a [2] da 4d [2] c6 62 }

  condition:
    any of them
}