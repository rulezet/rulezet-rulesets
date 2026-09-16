rule TTP_XOR_QUAD_CurrentVersionRun_47b3 {
  strings:
    $key_47b3 = { 14 dc [2] 30 d2 [2] 1b fe [2] 35 dc [2] 21 c7 [2] 2e dd [2] 30 c0 [2] 32 c1 [2] 29 c7 [2] 35 c0 [2] 29 ef }

  condition:
    any of them
}