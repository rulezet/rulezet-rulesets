rule TTP_XOR_QUAD_CurrentVersionRun_dfc9 {
  strings:
    $key_dfc9 = { 8c a6 [2] a8 a8 [2] 83 84 [2] ad a6 [2] b9 bd [2] b6 a7 [2] a8 ba [2] aa bb [2] b1 bd [2] ad ba [2] b1 95 }

  condition:
    any of them
}