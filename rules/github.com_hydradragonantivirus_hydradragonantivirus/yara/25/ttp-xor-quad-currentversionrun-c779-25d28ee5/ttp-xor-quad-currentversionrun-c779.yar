rule TTP_XOR_QUAD_CurrentVersionRun_c779 {
  strings:
    $key_c779 = { 94 16 [2] b0 18 [2] 9b 34 [2] b5 16 [2] a1 0d [2] ae 17 [2] b0 0a [2] b2 0b [2] a9 0d [2] b5 0a [2] a9 25 }

  condition:
    any of them
}