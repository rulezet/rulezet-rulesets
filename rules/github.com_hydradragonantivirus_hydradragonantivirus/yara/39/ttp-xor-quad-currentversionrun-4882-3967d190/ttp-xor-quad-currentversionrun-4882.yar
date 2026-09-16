rule TTP_XOR_QUAD_CurrentVersionRun_4882 {
  strings:
    $key_4882 = { 1b ed [2] 3f e3 [2] 14 cf [2] 3a ed [2] 2e f6 [2] 21 ec [2] 3f f1 [2] 3d f0 [2] 26 f6 [2] 3a f1 [2] 26 de }

  condition:
    any of them
}