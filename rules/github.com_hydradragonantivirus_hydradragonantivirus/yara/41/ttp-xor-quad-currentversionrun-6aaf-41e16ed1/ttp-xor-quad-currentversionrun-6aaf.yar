rule TTP_XOR_QUAD_CurrentVersionRun_6aaf {
  strings:
    $key_6aaf = { 39 c0 [2] 1d ce [2] 36 e2 [2] 18 c0 [2] 0c db [2] 03 c1 [2] 1d dc [2] 1f dd [2] 04 db [2] 18 dc [2] 04 f3 }

  condition:
    any of them
}