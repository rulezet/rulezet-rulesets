rule TTP_XOR_QUAD_CurrentVersionRun_d2cf {
  strings:
    $key_d2cf = { 81 a0 [2] a5 ae [2] 8e 82 [2] a0 a0 [2] b4 bb [2] bb a1 [2] a5 bc [2] a7 bd [2] bc bb [2] a0 bc [2] bc 93 }

  condition:
    any of them
}