rule TTP_XOR_QUAD_CurrentVersionRun_c7ed {
  strings:
    $key_c7ed = { 94 82 [2] b0 8c [2] 9b a0 [2] b5 82 [2] a1 99 [2] ae 83 [2] b0 9e [2] b2 9f [2] a9 99 [2] b5 9e [2] a9 b1 }

  condition:
    any of them
}