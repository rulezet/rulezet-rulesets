rule TTP_XOR_QUAD_CurrentVersionRun_d0cf {
  strings:
    $key_d0cf = { 83 a0 [2] a7 ae [2] 8c 82 [2] a2 a0 [2] b6 bb [2] b9 a1 [2] a7 bc [2] a5 bd [2] be bb [2] a2 bc [2] be 93 }

  condition:
    any of them
}