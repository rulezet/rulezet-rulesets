rule TTP_XOR_QUAD_CurrentVersionRun_1c82 {
  strings:
    $key_1c82 = { 4f ed [2] 6b e3 [2] 40 cf [2] 6e ed [2] 7a f6 [2] 75 ec [2] 6b f1 [2] 69 f0 [2] 72 f6 [2] 6e f1 [2] 72 de }

  condition:
    any of them
}