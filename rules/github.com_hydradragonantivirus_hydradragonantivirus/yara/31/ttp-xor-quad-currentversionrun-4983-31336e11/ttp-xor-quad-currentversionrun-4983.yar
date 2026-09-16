rule TTP_XOR_QUAD_CurrentVersionRun_4983 {
  strings:
    $key_4983 = { 1a ec [2] 3e e2 [2] 15 ce [2] 3b ec [2] 2f f7 [2] 20 ed [2] 3e f0 [2] 3c f1 [2] 27 f7 [2] 3b f0 [2] 27 df }

  condition:
    any of them
}