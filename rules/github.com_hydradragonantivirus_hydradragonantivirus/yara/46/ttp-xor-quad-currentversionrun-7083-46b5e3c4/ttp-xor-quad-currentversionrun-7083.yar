rule TTP_XOR_QUAD_CurrentVersionRun_7083 {
  strings:
    $key_7083 = { 23 ec [2] 07 e2 [2] 2c ce [2] 02 ec [2] 16 f7 [2] 19 ed [2] 07 f0 [2] 05 f1 [2] 1e f7 [2] 02 f0 [2] 1e df }

  condition:
    any of them
}