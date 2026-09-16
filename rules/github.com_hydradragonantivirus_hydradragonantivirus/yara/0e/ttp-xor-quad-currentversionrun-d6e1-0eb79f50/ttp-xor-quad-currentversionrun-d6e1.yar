rule TTP_XOR_QUAD_CurrentVersionRun_d6e1 {
  strings:
    $key_d6e1 = { 85 8e [2] a1 80 [2] 8a ac [2] a4 8e [2] b0 95 [2] bf 8f [2] a1 92 [2] a3 93 [2] b8 95 [2] a4 92 [2] b8 bd }

  condition:
    any of them
}