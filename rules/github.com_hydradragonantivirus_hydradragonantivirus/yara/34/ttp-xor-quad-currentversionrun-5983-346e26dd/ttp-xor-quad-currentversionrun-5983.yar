rule TTP_XOR_QUAD_CurrentVersionRun_5983 {
  strings:
    $key_5983 = { 0a ec [2] 2e e2 [2] 05 ce [2] 2b ec [2] 3f f7 [2] 30 ed [2] 2e f0 [2] 2c f1 [2] 37 f7 [2] 2b f0 [2] 37 df }

  condition:
    any of them
}