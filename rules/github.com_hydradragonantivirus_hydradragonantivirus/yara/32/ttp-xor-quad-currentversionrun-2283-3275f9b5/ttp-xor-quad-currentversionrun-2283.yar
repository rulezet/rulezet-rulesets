rule TTP_XOR_QUAD_CurrentVersionRun_2283 {
  strings:
    $key_2283 = { 71 ec [2] 55 e2 [2] 7e ce [2] 50 ec [2] 44 f7 [2] 4b ed [2] 55 f0 [2] 57 f1 [2] 4c f7 [2] 50 f0 [2] 4c df }

  condition:
    any of them
}