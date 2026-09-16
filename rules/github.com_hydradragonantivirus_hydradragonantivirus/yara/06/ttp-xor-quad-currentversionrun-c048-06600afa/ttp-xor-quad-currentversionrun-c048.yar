rule TTP_XOR_QUAD_CurrentVersionRun_c048 {
  strings:
    $key_c048 = { 93 27 [2] b7 29 [2] 9c 05 [2] b2 27 [2] a6 3c [2] a9 26 [2] b7 3b [2] b5 3a [2] ae 3c [2] b2 3b [2] ae 14 }

  condition:
    any of them
}