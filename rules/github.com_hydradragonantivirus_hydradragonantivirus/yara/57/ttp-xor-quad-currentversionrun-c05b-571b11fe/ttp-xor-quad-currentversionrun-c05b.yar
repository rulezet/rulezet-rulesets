rule TTP_XOR_QUAD_CurrentVersionRun_c05b {
  strings:
    $key_c05b = { 93 34 [2] b7 3a [2] 9c 16 [2] b2 34 [2] a6 2f [2] a9 35 [2] b7 28 [2] b5 29 [2] ae 2f [2] b2 28 [2] ae 07 }

  condition:
    any of them
}