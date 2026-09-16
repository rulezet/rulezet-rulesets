rule TTP_XOR_QUAD_CurrentVersionRun_c680 {
  strings:
    $key_c680 = { 95 ef [2] b1 e1 [2] 9a cd [2] b4 ef [2] a0 f4 [2] af ee [2] b1 f3 [2] b3 f2 [2] a8 f4 [2] b4 f3 [2] a8 dc }

  condition:
    any of them
}