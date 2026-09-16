rule TTP_XOR_QUAD_CurrentVersionRun_36b3 {
  strings:
    $key_36b3 = { 65 dc [2] 41 d2 [2] 6a fe [2] 44 dc [2] 50 c7 [2] 5f dd [2] 41 c0 [2] 43 c1 [2] 58 c7 [2] 44 c0 [2] 58 ef }

  condition:
    any of them
}