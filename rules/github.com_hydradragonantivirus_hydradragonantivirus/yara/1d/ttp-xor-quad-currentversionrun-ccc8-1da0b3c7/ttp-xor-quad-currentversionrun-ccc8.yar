rule TTP_XOR_QUAD_CurrentVersionRun_ccc8 {
  strings:
    $key_ccc8 = { 9f a7 [2] bb a9 [2] 90 85 [2] be a7 [2] aa bc [2] a5 a6 [2] bb bb [2] b9 ba [2] a2 bc [2] be bb [2] a2 94 }

  condition:
    any of them
}