rule TTP_XOR_QUAD_CurrentVersionRun_c768 {
  strings:
    $key_c768 = { 94 07 [2] b0 09 [2] 9b 25 [2] b5 07 [2] a1 1c [2] ae 06 [2] b0 1b [2] b2 1a [2] a9 1c [2] b5 1b [2] a9 34 }

  condition:
    any of them
}