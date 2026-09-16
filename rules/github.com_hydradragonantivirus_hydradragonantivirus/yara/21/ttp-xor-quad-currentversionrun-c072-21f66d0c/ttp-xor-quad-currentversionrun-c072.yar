rule TTP_XOR_QUAD_CurrentVersionRun_c072 {
  strings:
    $key_c072 = { 93 1d [2] b7 13 [2] 9c 3f [2] b2 1d [2] a6 06 [2] a9 1c [2] b7 01 [2] b5 00 [2] ae 06 [2] b2 01 [2] ae 2e }

  condition:
    any of them
}