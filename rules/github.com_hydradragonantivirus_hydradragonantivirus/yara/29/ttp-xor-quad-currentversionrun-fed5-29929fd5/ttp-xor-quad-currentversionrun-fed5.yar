rule TTP_XOR_QUAD_CurrentVersionRun_fed5 {
  strings:
    $key_fed5 = { ad ba [2] 89 b4 [2] a2 98 [2] 8c ba [2] 98 a1 [2] 97 bb [2] 89 a6 [2] 8b a7 [2] 90 a1 [2] 8c a6 [2] 90 89 }

  condition:
    any of them
}