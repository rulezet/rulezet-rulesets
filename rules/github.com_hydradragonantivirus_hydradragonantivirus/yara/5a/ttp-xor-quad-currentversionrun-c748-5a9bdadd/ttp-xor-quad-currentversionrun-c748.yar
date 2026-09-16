rule TTP_XOR_QUAD_CurrentVersionRun_c748 {
  strings:
    $key_c748 = { 94 27 [2] b0 29 [2] 9b 05 [2] b5 27 [2] a1 3c [2] ae 26 [2] b0 3b [2] b2 3a [2] a9 3c [2] b5 3b [2] a9 14 }

  condition:
    any of them
}