rule TTP_XOR_QUAD_CurrentVersionRun_c047 {
  strings:
    $key_c047 = { 93 28 [2] b7 26 [2] 9c 0a [2] b2 28 [2] a6 33 [2] a9 29 [2] b7 34 [2] b5 35 [2] ae 33 [2] b2 34 [2] ae 1b }

  condition:
    any of them
}