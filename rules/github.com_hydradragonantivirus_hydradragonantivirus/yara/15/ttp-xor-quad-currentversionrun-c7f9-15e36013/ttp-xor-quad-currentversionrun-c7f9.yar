rule TTP_XOR_QUAD_CurrentVersionRun_c7f9 {
  strings:
    $key_c7f9 = { 94 96 [2] b0 98 [2] 9b b4 [2] b5 96 [2] a1 8d [2] ae 97 [2] b0 8a [2] b2 8b [2] a9 8d [2] b5 8a [2] a9 a5 }

  condition:
    any of them
}