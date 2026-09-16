rule TTP_XOR_QUAD_CurrentVersionRun_c7ec {
  strings:
    $key_c7ec = { 94 83 [2] b0 8d [2] 9b a1 [2] b5 83 [2] a1 98 [2] ae 82 [2] b0 9f [2] b2 9e [2] a9 98 [2] b5 9f [2] a9 b0 }

  condition:
    any of them
}