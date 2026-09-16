rule TTP_XOR_QUAD_CurrentVersionRun_a85e {
  strings:
    $key_a85e = { fb 31 [2] df 3f [2] f4 13 [2] da 31 [2] ce 2a [2] c1 30 [2] df 2d [2] dd 2c [2] c6 2a [2] da 2d [2] c6 02 }

  condition:
    any of them
}