rule TTP_XOR_QUAD_CurrentVersionRun_5c82 {
  strings:
    $key_5c82 = { 0f ed [2] 2b e3 [2] 00 cf [2] 2e ed [2] 3a f6 [2] 35 ec [2] 2b f1 [2] 29 f0 [2] 32 f6 [2] 2e f1 [2] 32 de }

  condition:
    any of them
}