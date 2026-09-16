rule TTP_XOR_QUAD_CurrentVersionRun_c04b {
  strings:
    $key_c04b = { 93 24 [2] b7 2a [2] 9c 06 [2] b2 24 [2] a6 3f [2] a9 25 [2] b7 38 [2] b5 39 [2] ae 3f [2] b2 38 [2] ae 17 }

  condition:
    any of them
}