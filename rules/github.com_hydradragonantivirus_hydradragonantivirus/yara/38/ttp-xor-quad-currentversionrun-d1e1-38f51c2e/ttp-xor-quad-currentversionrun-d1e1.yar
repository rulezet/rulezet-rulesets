rule TTP_XOR_QUAD_CurrentVersionRun_d1e1 {
  strings:
    $key_d1e1 = { 82 8e [2] a6 80 [2] 8d ac [2] a3 8e [2] b7 95 [2] b8 8f [2] a6 92 [2] a4 93 [2] bf 95 [2] a3 92 [2] bf bd }

  condition:
    any of them
}