rule TTP_XOR_QUAD_CurrentVersionRun_cccf {
  strings:
    $key_cccf = { 9f a0 [2] bb ae [2] 90 82 [2] be a0 [2] aa bb [2] a5 a1 [2] bb bc [2] b9 bd [2] a2 bb [2] be bc [2] a2 93 }

  condition:
    any of them
}