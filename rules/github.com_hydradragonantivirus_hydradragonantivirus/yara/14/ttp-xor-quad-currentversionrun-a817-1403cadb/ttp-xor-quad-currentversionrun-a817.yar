rule TTP_XOR_QUAD_CurrentVersionRun_a817 {
  strings:
    $key_a817 = { fb 78 [2] df 76 [2] f4 5a [2] da 78 [2] ce 63 [2] c1 79 [2] df 64 [2] dd 65 [2] c6 63 [2] da 64 [2] c6 4b }

  condition:
    any of them
}