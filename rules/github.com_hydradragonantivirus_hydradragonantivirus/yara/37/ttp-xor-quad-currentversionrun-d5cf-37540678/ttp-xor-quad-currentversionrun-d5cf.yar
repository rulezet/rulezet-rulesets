rule TTP_XOR_QUAD_CurrentVersionRun_d5cf {
  strings:
    $key_d5cf = { 86 a0 [2] a2 ae [2] 89 82 [2] a7 a0 [2] b3 bb [2] bc a1 [2] a2 bc [2] a0 bd [2] bb bb [2] a7 bc [2] bb 93 }

  condition:
    any of them
}