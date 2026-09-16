rule TTP_XOR_QUAD_CurrentVersionRun_c4d2 {
  strings:
    $key_c4d2 = { 97 bd [2] b3 b3 [2] 98 9f [2] b6 bd [2] a2 a6 [2] ad bc [2] b3 a1 [2] b1 a0 [2] aa a6 [2] b6 a1 [2] aa 8e }

  condition:
    any of them
}