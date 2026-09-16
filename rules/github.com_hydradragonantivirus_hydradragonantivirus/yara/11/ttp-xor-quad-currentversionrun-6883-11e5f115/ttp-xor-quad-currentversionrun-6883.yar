rule TTP_XOR_QUAD_CurrentVersionRun_6883 {
  strings:
    $key_6883 = { 3b ec [2] 1f e2 [2] 34 ce [2] 1a ec [2] 0e f7 [2] 01 ed [2] 1f f0 [2] 1d f1 [2] 06 f7 [2] 1a f0 [2] 06 df }

  condition:
    any of them
}