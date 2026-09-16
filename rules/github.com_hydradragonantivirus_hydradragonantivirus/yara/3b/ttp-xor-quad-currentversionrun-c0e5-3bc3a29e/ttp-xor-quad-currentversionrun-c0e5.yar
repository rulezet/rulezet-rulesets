rule TTP_XOR_QUAD_CurrentVersionRun_c0e5 {
  strings:
    $key_c0e5 = { 93 8a [2] b7 84 [2] 9c a8 [2] b2 8a [2] a6 91 [2] a9 8b [2] b7 96 [2] b5 97 [2] ae 91 [2] b2 96 [2] ae b9 }

  condition:
    any of them
}