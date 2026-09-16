rule TTP_XOR_QUAD_CurrentVersionRun_c7e5 {
  strings:
    $key_c7e5 = { 94 8a [2] b0 84 [2] 9b a8 [2] b5 8a [2] a1 91 [2] ae 8b [2] b0 96 [2] b2 97 [2] a9 91 [2] b5 96 [2] a9 b9 }

  condition:
    any of them
}