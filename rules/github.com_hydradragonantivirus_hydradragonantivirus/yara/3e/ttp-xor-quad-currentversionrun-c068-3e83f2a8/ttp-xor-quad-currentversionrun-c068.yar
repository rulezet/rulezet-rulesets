rule TTP_XOR_QUAD_CurrentVersionRun_c068 {
  strings:
    $key_c068 = { 93 07 [2] b7 09 [2] 9c 25 [2] b2 07 [2] a6 1c [2] a9 06 [2] b7 1b [2] b5 1a [2] ae 1c [2] b2 1b [2] ae 34 }

  condition:
    any of them
}