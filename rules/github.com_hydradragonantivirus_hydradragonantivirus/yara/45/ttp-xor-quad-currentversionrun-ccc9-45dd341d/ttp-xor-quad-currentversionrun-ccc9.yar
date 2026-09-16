rule TTP_XOR_QUAD_CurrentVersionRun_ccc9 {
  strings:
    $key_ccc9 = { 9f a6 [2] bb a8 [2] 90 84 [2] be a6 [2] aa bd [2] a5 a7 [2] bb ba [2] b9 bb [2] a2 bd [2] be ba [2] a2 95 }

  condition:
    any of them
}