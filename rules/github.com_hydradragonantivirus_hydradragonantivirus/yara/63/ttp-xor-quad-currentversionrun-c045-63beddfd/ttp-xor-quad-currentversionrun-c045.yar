rule TTP_XOR_QUAD_CurrentVersionRun_c045 {
  strings:
    $key_c045 = { 93 2a [2] b7 24 [2] 9c 08 [2] b2 2a [2] a6 31 [2] a9 2b [2] b7 36 [2] b5 37 [2] ae 31 [2] b2 36 [2] ae 19 }

  condition:
    any of them
}