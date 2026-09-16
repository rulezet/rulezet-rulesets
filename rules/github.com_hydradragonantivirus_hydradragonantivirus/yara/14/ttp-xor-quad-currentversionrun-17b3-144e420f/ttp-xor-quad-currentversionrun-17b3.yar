rule TTP_XOR_QUAD_CurrentVersionRun_17b3 {
  strings:
    $key_17b3 = { 44 dc [2] 60 d2 [2] 4b fe [2] 65 dc [2] 71 c7 [2] 7e dd [2] 60 c0 [2] 62 c1 [2] 79 c7 [2] 65 c0 [2] 79 ef }

  condition:
    any of them
}