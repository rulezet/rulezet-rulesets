rule TTP_XOR_QUAD_CurrentVersionRun_3383 {
  strings:
    $key_3383 = { 60 ec [2] 44 e2 [2] 6f ce [2] 41 ec [2] 55 f7 [2] 5a ed [2] 44 f0 [2] 46 f1 [2] 5d f7 [2] 41 f0 [2] 5d df }

  condition:
    any of them
}