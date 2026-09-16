rule TTP_XOR_QUAD_CurrentVersionRun_2aaf {
  strings:
    $key_2aaf = { 79 c0 [2] 5d ce [2] 76 e2 [2] 58 c0 [2] 4c db [2] 43 c1 [2] 5d dc [2] 5f dd [2] 44 db [2] 58 dc [2] 44 f3 }

  condition:
    any of them
}