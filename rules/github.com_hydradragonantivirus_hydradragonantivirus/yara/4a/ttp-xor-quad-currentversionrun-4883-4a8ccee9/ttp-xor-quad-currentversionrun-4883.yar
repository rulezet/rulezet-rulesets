rule TTP_XOR_QUAD_CurrentVersionRun_4883 {
  strings:
    $key_4883 = { 1b ec [2] 3f e2 [2] 14 ce [2] 3a ec [2] 2e f7 [2] 21 ed [2] 3f f0 [2] 3d f1 [2] 26 f7 [2] 3a f0 [2] 26 df }

  condition:
    any of them
}