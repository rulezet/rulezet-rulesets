rule TTP_XOR_QUAD_CurrentVersionRun_a815 {
  strings:
    $key_a815 = { fb 7a [2] df 74 [2] f4 58 [2] da 7a [2] ce 61 [2] c1 7b [2] df 66 [2] dd 67 [2] c6 61 [2] da 66 [2] c6 49 }

  condition:
    any of them
}