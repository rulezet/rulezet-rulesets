rule TTP_XOR_QUAD_CurrentVersionRun_d691 {
  strings:
    $key_d691 = { 85 fe [2] a1 f0 [2] 8a dc [2] a4 fe [2] b0 e5 [2] bf ff [2] a1 e2 [2] a3 e3 [2] b8 e5 [2] a4 e2 [2] b8 cd }

  condition:
    any of them
}