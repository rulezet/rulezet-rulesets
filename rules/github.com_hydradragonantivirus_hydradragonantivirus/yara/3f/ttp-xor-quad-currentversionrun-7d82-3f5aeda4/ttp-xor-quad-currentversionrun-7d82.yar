rule TTP_XOR_QUAD_CurrentVersionRun_7d82 {
  strings:
    $key_7d82 = { 2e ed [2] 0a e3 [2] 21 cf [2] 0f ed [2] 1b f6 [2] 14 ec [2] 0a f1 [2] 08 f0 [2] 13 f6 [2] 0f f1 [2] 13 de }

  condition:
    any of them
}