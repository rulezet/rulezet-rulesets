rule TTP_XOR_QUAD_CurrentVersionRun_c6cf {
  strings:
    $key_c6cf = { 95 a0 [2] b1 ae [2] 9a 82 [2] b4 a0 [2] a0 bb [2] af a1 [2] b1 bc [2] b3 bd [2] a8 bb [2] b4 bc [2] a8 93 }

  condition:
    any of them
}