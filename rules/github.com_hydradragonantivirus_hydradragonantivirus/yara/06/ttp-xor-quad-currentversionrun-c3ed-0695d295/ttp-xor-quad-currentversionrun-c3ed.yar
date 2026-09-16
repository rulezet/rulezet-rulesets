rule TTP_XOR_QUAD_CurrentVersionRun_c3ed {
  strings:
    $key_c3ed = { 90 82 [2] b4 8c [2] 9f a0 [2] b1 82 [2] a5 99 [2] aa 83 [2] b4 9e [2] b6 9f [2] ad 99 [2] b1 9e [2] ad b1 }

  condition:
    any of them
}