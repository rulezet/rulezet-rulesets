rule TTP_XOR_QUAD_CurrentVersionRun_c069 {
  strings:
    $key_c069 = { 93 06 [2] b7 08 [2] 9c 24 [2] b2 06 [2] a6 1d [2] a9 07 [2] b7 1a [2] b5 1b [2] ae 1d [2] b2 1a [2] ae 35 }

  condition:
    any of them
}