rule TTP_XOR_QUAD_CurrentVersionRun_6d82 {
  strings:
    $key_6d82 = { 3e ed [2] 1a e3 [2] 31 cf [2] 1f ed [2] 0b f6 [2] 04 ec [2] 1a f1 [2] 18 f0 [2] 03 f6 [2] 1f f1 [2] 03 de }

  condition:
    any of them
}