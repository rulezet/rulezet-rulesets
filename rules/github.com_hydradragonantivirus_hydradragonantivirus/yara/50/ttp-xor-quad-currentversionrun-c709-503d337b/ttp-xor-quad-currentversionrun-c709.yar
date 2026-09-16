rule TTP_XOR_QUAD_CurrentVersionRun_c709 {
  strings:
    $key_c709 = { 94 66 [2] b0 68 [2] 9b 44 [2] b5 66 [2] a1 7d [2] ae 67 [2] b0 7a [2] b2 7b [2] a9 7d [2] b5 7a [2] a9 55 }

  condition:
    any of them
}