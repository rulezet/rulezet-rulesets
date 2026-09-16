rule TTP_XOR_QUAD_CurrentVersionRun_c691 {
  strings:
    $key_c691 = { 95 fe [2] b1 f0 [2] 9a dc [2] b4 fe [2] a0 e5 [2] af ff [2] b1 e2 [2] b3 e3 [2] a8 e5 [2] b4 e2 [2] a8 cd }

  condition:
    any of them
}