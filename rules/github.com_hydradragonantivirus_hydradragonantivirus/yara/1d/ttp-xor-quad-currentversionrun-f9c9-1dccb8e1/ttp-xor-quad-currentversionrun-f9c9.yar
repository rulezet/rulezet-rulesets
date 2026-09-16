rule TTP_XOR_QUAD_CurrentVersionRun_f9c9 {
  strings:
    $key_f9c9 = { aa a6 [2] 8e a8 [2] a5 84 [2] 8b a6 [2] 9f bd [2] 90 a7 [2] 8e ba [2] 8c bb [2] 97 bd [2] 8b ba [2] 97 95 }

  condition:
    any of them
}