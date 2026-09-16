rule TTP_XOR_QUAD_CurrentVersionRun_c0e4 {
  strings:
    $key_c0e4 = { 93 8b [2] b7 85 [2] 9c a9 [2] b2 8b [2] a6 90 [2] a9 8a [2] b7 97 [2] b5 96 [2] ae 90 [2] b2 97 [2] ae b8 }

  condition:
    any of them
}