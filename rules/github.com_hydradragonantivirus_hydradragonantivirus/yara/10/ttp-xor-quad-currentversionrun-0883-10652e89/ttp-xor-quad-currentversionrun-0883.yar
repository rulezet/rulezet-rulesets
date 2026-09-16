rule TTP_XOR_QUAD_CurrentVersionRun_0883 {
  strings:
    $key_0883 = { 5b ec [2] 7f e2 [2] 54 ce [2] 7a ec [2] 6e f7 [2] 61 ed [2] 7f f0 [2] 7d f1 [2] 66 f7 [2] 7a f0 [2] 66 df }

  condition:
    any of them
}