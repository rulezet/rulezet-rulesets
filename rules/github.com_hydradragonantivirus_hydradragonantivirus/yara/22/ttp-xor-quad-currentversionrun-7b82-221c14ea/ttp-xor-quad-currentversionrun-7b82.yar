rule TTP_XOR_QUAD_CurrentVersionRun_7b82 {
  strings:
    $key_7b82 = { 28 ed [2] 0c e3 [2] 27 cf [2] 09 ed [2] 1d f6 [2] 12 ec [2] 0c f1 [2] 0e f0 [2] 15 f6 [2] 09 f1 [2] 15 de }

  condition:
    any of them
}