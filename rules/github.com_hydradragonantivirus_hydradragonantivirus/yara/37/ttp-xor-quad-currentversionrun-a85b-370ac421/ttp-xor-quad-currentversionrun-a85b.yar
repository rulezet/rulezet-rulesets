rule TTP_XOR_QUAD_CurrentVersionRun_a85b {
  strings:
    $key_a85b = { fb 34 [2] df 3a [2] f4 16 [2] da 34 [2] ce 2f [2] c1 35 [2] df 28 [2] dd 29 [2] c6 2f [2] da 28 [2] c6 07 }

  condition:
    any of them
}