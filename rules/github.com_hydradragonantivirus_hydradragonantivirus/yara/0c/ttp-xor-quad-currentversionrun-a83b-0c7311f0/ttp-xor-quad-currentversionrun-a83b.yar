rule TTP_XOR_QUAD_CurrentVersionRun_a83b {
  strings:
    $key_a83b = { fb 54 [2] df 5a [2] f4 76 [2] da 54 [2] ce 4f [2] c1 55 [2] df 48 [2] dd 49 [2] c6 4f [2] da 48 [2] c6 67 }

  condition:
    any of them
}