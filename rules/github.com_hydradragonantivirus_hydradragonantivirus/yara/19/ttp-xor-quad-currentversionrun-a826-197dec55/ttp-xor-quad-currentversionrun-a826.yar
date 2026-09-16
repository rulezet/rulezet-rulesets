rule TTP_XOR_QUAD_CurrentVersionRun_a826 {
  strings:
    $key_a826 = { fb 49 [2] df 47 [2] f4 6b [2] da 49 [2] ce 52 [2] c1 48 [2] df 55 [2] dd 54 [2] c6 52 [2] da 55 [2] c6 7a }

  condition:
    any of them
}