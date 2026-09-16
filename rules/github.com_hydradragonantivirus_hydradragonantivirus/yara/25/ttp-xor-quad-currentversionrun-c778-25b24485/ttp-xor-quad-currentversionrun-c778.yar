rule TTP_XOR_QUAD_CurrentVersionRun_c778 {
  strings:
    $key_c778 = { 94 17 [2] b0 19 [2] 9b 35 [2] b5 17 [2] a1 0c [2] ae 16 [2] b0 0b [2] b2 0a [2] a9 0c [2] b5 0b [2] a9 24 }

  condition:
    any of them
}