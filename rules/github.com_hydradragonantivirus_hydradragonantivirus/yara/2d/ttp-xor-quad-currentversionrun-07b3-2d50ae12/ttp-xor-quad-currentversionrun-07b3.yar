rule TTP_XOR_QUAD_CurrentVersionRun_07b3 {
  strings:
    $key_07b3 = { 54 dc [2] 70 d2 [2] 5b fe [2] 75 dc [2] 61 c7 [2] 6e dd [2] 70 c0 [2] 72 c1 [2] 69 c7 [2] 75 c0 [2] 69 ef }

  condition:
    any of them
}