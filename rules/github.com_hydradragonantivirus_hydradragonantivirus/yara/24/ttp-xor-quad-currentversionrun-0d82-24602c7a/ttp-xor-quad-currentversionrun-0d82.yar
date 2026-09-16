rule TTP_XOR_QUAD_CurrentVersionRun_0d82 {
  strings:
    $key_0d82 = { 5e ed [2] 7a e3 [2] 51 cf [2] 7f ed [2] 6b f6 [2] 64 ec [2] 7a f1 [2] 78 f0 [2] 63 f6 [2] 7f f1 [2] 63 de }

  condition:
    any of them
}