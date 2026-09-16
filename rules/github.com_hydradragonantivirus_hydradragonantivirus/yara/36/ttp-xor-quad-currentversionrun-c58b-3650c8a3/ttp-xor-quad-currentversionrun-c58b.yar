rule TTP_XOR_QUAD_CurrentVersionRun_c58b {
  strings:
    $key_c58b = { 96 e4 [2] b2 ea [2] 99 c6 [2] b7 e4 [2] a3 ff [2] ac e5 [2] b2 f8 [2] b0 f9 [2] ab ff [2] b7 f8 [2] ab d7 }

  condition:
    any of them
}