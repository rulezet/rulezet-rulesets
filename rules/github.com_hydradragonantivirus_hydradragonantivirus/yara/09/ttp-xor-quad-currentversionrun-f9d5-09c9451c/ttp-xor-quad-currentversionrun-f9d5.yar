rule TTP_XOR_QUAD_CurrentVersionRun_f9d5 {
  strings:
    $key_f9d5 = { aa ba [2] 8e b4 [2] a5 98 [2] 8b ba [2] 9f a1 [2] 90 bb [2] 8e a6 [2] 8c a7 [2] 97 a1 [2] 8b a6 [2] 97 89 }

  condition:
    any of them
}