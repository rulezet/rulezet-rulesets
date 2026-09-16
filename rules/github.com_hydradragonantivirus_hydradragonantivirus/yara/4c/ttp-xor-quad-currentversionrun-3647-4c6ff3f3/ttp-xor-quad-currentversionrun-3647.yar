rule TTP_XOR_QUAD_CurrentVersionRun_3647 {
  strings:
    $key_3647 = { 65 28 [2] 41 26 [2] 6a 0a [2] 44 28 [2] 50 33 [2] 5f 29 [2] 41 34 [2] 43 35 [2] 58 33 [2] 44 34 [2] 58 1b }

  condition:
    any of them
}