rule TTP_XOR_QUAD_CurrentVersionRun_6283 {
  strings:
    $key_6283 = { 31 ec [2] 15 e2 [2] 3e ce [2] 10 ec [2] 04 f7 [2] 0b ed [2] 15 f0 [2] 17 f1 [2] 0c f7 [2] 10 f0 [2] 0c df }

  condition:
    any of them
}