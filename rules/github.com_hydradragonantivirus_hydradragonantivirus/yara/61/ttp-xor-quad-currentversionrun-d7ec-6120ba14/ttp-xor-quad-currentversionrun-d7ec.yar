rule TTP_XOR_QUAD_CurrentVersionRun_d7ec {
  strings:
    $key_d7ec = { 84 83 [2] a0 8d [2] 8b a1 [2] a5 83 [2] b1 98 [2] be 82 [2] a0 9f [2] a2 9e [2] b9 98 [2] a5 9f [2] b9 b0 }

  condition:
    any of them
}