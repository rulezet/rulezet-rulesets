rule TTP_XOR_QUAD_CurrentVersionRun_c073 {
  strings:
    $key_c073 = { 93 1c [2] b7 12 [2] 9c 3e [2] b2 1c [2] a6 07 [2] a9 1d [2] b7 00 [2] b5 01 [2] ae 07 [2] b2 00 [2] ae 2f }

  condition:
    any of them
}