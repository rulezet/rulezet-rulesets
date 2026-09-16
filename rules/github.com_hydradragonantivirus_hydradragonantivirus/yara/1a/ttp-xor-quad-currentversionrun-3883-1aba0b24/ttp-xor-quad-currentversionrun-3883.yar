rule TTP_XOR_QUAD_CurrentVersionRun_3883 {
  strings:
    $key_3883 = { 6b ec [2] 4f e2 [2] 64 ce [2] 4a ec [2] 5e f7 [2] 51 ed [2] 4f f0 [2] 4d f1 [2] 56 f7 [2] 4a f0 [2] 56 df }

  condition:
    any of them
}