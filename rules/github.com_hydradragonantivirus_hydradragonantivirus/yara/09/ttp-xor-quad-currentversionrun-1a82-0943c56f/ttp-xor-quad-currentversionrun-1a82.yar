rule TTP_XOR_QUAD_CurrentVersionRun_1a82 {
  strings:
    $key_1a82 = { 49 ed [2] 6d e3 [2] 46 cf [2] 68 ed [2] 7c f6 [2] 73 ec [2] 6d f1 [2] 6f f0 [2] 74 f6 [2] 68 f1 [2] 74 de }

  condition:
    any of them
}