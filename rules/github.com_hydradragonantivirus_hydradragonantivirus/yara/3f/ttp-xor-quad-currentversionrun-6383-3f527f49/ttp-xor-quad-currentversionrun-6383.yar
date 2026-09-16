rule TTP_XOR_QUAD_CurrentVersionRun_6383 {
  strings:
    $key_6383 = { 30 ec [2] 14 e2 [2] 3f ce [2] 11 ec [2] 05 f7 [2] 0a ed [2] 14 f0 [2] 16 f1 [2] 0d f7 [2] 11 f0 [2] 0d df }

  condition:
    any of them
}