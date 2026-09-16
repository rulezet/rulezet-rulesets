rule TTP_XOR_QUAD_CurrentVersionRun_d7ef {
  strings:
    $key_d7ef = { 84 80 [2] a0 8e [2] 8b a2 [2] a5 80 [2] b1 9b [2] be 81 [2] a0 9c [2] a2 9d [2] b9 9b [2] a5 9c [2] b9 b3 }

  condition:
    any of them
}