rule TTP_XOR_QUAD_CurrentVersionRun_0737 {
  strings:
    $key_0737 = { 54 58 [2] 70 56 [2] 5b 7a [2] 75 58 [2] 61 43 [2] 6e 59 [2] 70 44 [2] 72 45 [2] 69 43 [2] 75 44 [2] 69 6b }

  condition:
    any of them
}