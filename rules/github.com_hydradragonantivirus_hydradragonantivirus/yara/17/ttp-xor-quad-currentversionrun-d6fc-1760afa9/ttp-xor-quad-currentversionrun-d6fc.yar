rule TTP_XOR_QUAD_CurrentVersionRun_d6fc {
  strings:
    $key_d6fc = { 85 93 [2] a1 9d [2] 8a b1 [2] a4 93 [2] b0 88 [2] bf 92 [2] a1 8f [2] a3 8e [2] b8 88 [2] a4 8f [2] b8 a0 }

  condition:
    any of them
}