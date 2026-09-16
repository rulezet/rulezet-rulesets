rule TTP_XOR_QUAD_CurrentVersionRun_5383 {
  strings:
    $key_5383 = { 00 ec [2] 24 e2 [2] 0f ce [2] 21 ec [2] 35 f7 [2] 3a ed [2] 24 f0 [2] 26 f1 [2] 3d f7 [2] 21 f0 [2] 3d df }

  condition:
    any of them
}