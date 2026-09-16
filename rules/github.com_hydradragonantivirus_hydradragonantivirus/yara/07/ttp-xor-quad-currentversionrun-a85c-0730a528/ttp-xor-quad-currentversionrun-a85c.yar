rule TTP_XOR_QUAD_CurrentVersionRun_a85c {
  strings:
    $key_a85c = { fb 33 [2] df 3d [2] f4 11 [2] da 33 [2] ce 28 [2] c1 32 [2] df 2f [2] dd 2e [2] c6 28 [2] da 2f [2] c6 00 }

  condition:
    any of them
}