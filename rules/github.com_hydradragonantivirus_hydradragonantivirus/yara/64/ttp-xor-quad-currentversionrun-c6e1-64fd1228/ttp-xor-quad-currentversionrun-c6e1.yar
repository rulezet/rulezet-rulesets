rule TTP_XOR_QUAD_CurrentVersionRun_c6e1 {
  strings:
    $key_c6e1 = { 95 8e [2] b1 80 [2] 9a ac [2] b4 8e [2] a0 95 [2] af 8f [2] b1 92 [2] b3 93 [2] a8 95 [2] b4 92 [2] a8 bd }

  condition:
    any of them
}