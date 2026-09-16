rule TTP_XOR_QUAD_CurrentVersionRun_c3ec {
  strings:
    $key_c3ec = { 90 83 [2] b4 8d [2] 9f a1 [2] b1 83 [2] a5 98 [2] aa 82 [2] b4 9f [2] b6 9e [2] ad 98 [2] b1 9f [2] ad b0 }

  condition:
    any of them
}