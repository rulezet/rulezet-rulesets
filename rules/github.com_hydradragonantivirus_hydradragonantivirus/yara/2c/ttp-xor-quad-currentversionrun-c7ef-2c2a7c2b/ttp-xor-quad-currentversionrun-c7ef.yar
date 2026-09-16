rule TTP_XOR_QUAD_CurrentVersionRun_c7ef {
  strings:
    $key_c7ef = { 94 80 [2] b0 8e [2] 9b a2 [2] b5 80 [2] a1 9b [2] ae 81 [2] b0 9c [2] b2 9d [2] a9 9b [2] b5 9c [2] a9 b3 }

  condition:
    any of them
}