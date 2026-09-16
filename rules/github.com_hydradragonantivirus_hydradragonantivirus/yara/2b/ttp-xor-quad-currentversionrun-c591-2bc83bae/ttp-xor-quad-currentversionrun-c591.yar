rule TTP_XOR_QUAD_CurrentVersionRun_c591 {
  strings:
    $key_c591 = { 96 fe [2] b2 f0 [2] 99 dc [2] b7 fe [2] a3 e5 [2] ac ff [2] b2 e2 [2] b0 e3 [2] ab e5 [2] b7 e2 [2] ab cd }

  condition:
    any of them
}