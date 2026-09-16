rule TTP_XOR_QUAD_CurrentVersionRun_27b3 {
  strings:
    $key_27b3 = { 74 dc [2] 50 d2 [2] 7b fe [2] 55 dc [2] 41 c7 [2] 4e dd [2] 50 c0 [2] 52 c1 [2] 49 c7 [2] 55 c0 [2] 49 ef }

  condition:
    any of them
}