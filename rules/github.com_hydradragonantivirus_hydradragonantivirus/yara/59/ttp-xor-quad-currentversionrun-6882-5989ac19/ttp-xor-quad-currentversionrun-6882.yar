rule TTP_XOR_QUAD_CurrentVersionRun_6882 {
  strings:
    $key_6882 = { 3b ed [2] 1f e3 [2] 34 cf [2] 1a ed [2] 0e f6 [2] 01 ec [2] 1f f1 [2] 1d f0 [2] 06 f6 [2] 1a f1 [2] 06 de }

  condition:
    any of them
}