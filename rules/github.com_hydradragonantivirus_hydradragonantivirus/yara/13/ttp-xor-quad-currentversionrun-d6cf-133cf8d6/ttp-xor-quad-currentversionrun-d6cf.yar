rule TTP_XOR_QUAD_CurrentVersionRun_d6cf {
  strings:
    $key_d6cf = { 85 a0 [2] a1 ae [2] 8a 82 [2] a4 a0 [2] b0 bb [2] bf a1 [2] a1 bc [2] a3 bd [2] b8 bb [2] a4 bc [2] b8 93 }

  condition:
    any of them
}