rule TTP_XOR_QUAD_CurrentVersionRun_d8ce {
  strings:
    $key_d8ce = { 8b a1 [2] af af [2] 84 83 [2] aa a1 [2] be ba [2] b1 a0 [2] af bd [2] ad bc [2] b6 ba [2] aa bd [2] b6 92 }

  condition:
    any of them
}