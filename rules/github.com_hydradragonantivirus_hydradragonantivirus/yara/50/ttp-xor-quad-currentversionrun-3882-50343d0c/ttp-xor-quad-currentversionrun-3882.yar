rule TTP_XOR_QUAD_CurrentVersionRun_3882 {
  strings:
    $key_3882 = { 6b ed [2] 4f e3 [2] 64 cf [2] 4a ed [2] 5e f6 [2] 51 ec [2] 4f f1 [2] 4d f0 [2] 56 f6 [2] 4a f1 [2] 56 de }

  condition:
    any of them
}