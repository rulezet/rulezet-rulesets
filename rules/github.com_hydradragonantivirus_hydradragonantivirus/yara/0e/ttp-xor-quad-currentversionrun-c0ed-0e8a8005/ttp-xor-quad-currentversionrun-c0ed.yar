rule TTP_XOR_QUAD_CurrentVersionRun_c0ed {
  strings:
    $key_c0ed = { 93 82 [2] b7 8c [2] 9c a0 [2] b2 82 [2] a6 99 [2] a9 83 [2] b7 9e [2] b5 9f [2] ae 99 [2] b2 9e [2] ae b1 }

  condition:
    any of them
}