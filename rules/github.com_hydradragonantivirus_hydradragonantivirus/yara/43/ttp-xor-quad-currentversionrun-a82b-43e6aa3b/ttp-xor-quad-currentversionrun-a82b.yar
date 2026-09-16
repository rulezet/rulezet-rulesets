rule TTP_XOR_QUAD_CurrentVersionRun_a82b {
  strings:
    $key_a82b = { fb 44 [2] df 4a [2] f4 66 [2] da 44 [2] ce 5f [2] c1 45 [2] df 58 [2] dd 59 [2] c6 5f [2] da 58 [2] c6 77 }

  condition:
    any of them
}