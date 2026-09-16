rule TTP_XOR_QUAD_CurrentVersionRun_e383 {
  strings:
    $key_e383 = { b0 ec [2] 94 e2 [2] bf ce [2] 91 ec [2] 85 f7 [2] 8a ed [2] 94 f0 [2] 96 f1 [2] 8d f7 [2] 91 f0 [2] 8d df }

  condition:
    any of them
}