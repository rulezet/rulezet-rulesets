rule TTP_XOR_QUAD_CurrentVersionRun_21d5 {
  strings:
    $key_21d5 = { 72 ba [2] 56 b4 [2] 7d 98 [2] 53 ba [2] 47 a1 [2] 48 bb [2] 56 a6 [2] 54 a7 [2] 4f a1 [2] 53 a6 [2] 4f 89 }

  condition:
    any of them
}