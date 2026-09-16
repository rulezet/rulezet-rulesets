rule TTP_XOR_QUAD_CurrentVersionRun_a8f9 {
  strings:
    $key_a8f9 = { fb 96 [2] df 98 [2] f4 b4 [2] da 96 [2] ce 8d [2] c1 97 [2] df 8a [2] dd 8b [2] c6 8d [2] da 8a [2] c6 a5 }

  condition:
    any of them
}