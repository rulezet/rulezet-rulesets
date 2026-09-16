rule TTP_XOR_QUAD_CurrentVersionRun_0283 {
  strings:
    $key_0283 = { 51 ec [2] 75 e2 [2] 5e ce [2] 70 ec [2] 64 f7 [2] 6b ed [2] 75 f0 [2] 77 f1 [2] 6c f7 [2] 70 f0 [2] 6c df }

  condition:
    any of them
}