rule TTP_XOR_QUAD_CurrentVersionRun_a806 {
  strings:
    $key_a806 = { fb 69 [2] df 67 [2] f4 4b [2] da 69 [2] ce 72 [2] c1 68 [2] df 75 [2] dd 74 [2] c6 72 [2] da 75 [2] c6 5a }

  condition:
    any of them
}