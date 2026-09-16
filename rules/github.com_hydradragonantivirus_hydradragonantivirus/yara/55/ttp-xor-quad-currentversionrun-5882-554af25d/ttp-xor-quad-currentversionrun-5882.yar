rule TTP_XOR_QUAD_CurrentVersionRun_5882 {
  strings:
    $key_5882 = { 0b ed [2] 2f e3 [2] 04 cf [2] 2a ed [2] 3e f6 [2] 31 ec [2] 2f f1 [2] 2d f0 [2] 36 f6 [2] 2a f1 [2] 36 de }

  condition:
    any of them
}