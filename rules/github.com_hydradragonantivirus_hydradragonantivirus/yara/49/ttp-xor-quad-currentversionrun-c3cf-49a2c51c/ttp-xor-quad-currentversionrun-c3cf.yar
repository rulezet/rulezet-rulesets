rule TTP_XOR_QUAD_CurrentVersionRun_c3cf {
  strings:
    $key_c3cf = { 90 a0 [2] b4 ae [2] 9f 82 [2] b1 a0 [2] a5 bb [2] aa a1 [2] b4 bc [2] b6 bd [2] ad bb [2] b1 bc [2] ad 93 }

  condition:
    any of them
}