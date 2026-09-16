rule TTP_XOR_QUAD_CurrentVersionRun_a85f {
  strings:
    $key_a85f = { fb 30 [2] df 3e [2] f4 12 [2] da 30 [2] ce 2b [2] c1 31 [2] df 2c [2] dd 2d [2] c6 2b [2] da 2c [2] c6 03 }

  condition:
    any of them
}