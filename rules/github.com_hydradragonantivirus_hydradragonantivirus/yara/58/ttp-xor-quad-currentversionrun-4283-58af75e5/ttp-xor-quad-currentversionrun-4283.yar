rule TTP_XOR_QUAD_CurrentVersionRun_4283 {
  strings:
    $key_4283 = { 11 ec [2] 35 e2 [2] 1e ce [2] 30 ec [2] 24 f7 [2] 2b ed [2] 35 f0 [2] 37 f1 [2] 2c f7 [2] 30 f0 [2] 2c df }

  condition:
    any of them
}