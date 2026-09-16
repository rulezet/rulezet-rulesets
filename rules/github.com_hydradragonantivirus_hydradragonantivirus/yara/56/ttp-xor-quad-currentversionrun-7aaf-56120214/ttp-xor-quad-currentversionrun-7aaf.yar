rule TTP_XOR_QUAD_CurrentVersionRun_7aaf {
  strings:
    $key_7aaf = { 29 c0 [2] 0d ce [2] 26 e2 [2] 08 c0 [2] 1c db [2] 13 c1 [2] 0d dc [2] 0f dd [2] 14 db [2] 08 dc [2] 14 f3 }

  condition:
    any of them
}