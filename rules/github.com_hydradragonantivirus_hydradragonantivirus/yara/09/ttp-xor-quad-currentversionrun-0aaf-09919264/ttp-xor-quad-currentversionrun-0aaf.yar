rule TTP_XOR_QUAD_CurrentVersionRun_0aaf {
  strings:
    $key_0aaf = { 59 c0 [2] 7d ce [2] 56 e2 [2] 78 c0 [2] 6c db [2] 63 c1 [2] 7d dc [2] 7f dd [2] 64 db [2] 78 dc [2] 64 f3 }

  condition:
    any of them
}