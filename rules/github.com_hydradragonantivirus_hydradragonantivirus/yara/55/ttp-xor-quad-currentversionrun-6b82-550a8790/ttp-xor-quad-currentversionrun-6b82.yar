rule TTP_XOR_QUAD_CurrentVersionRun_6b82 {
  strings:
    $key_6b82 = { 38 ed [2] 1c e3 [2] 37 cf [2] 19 ed [2] 0d f6 [2] 02 ec [2] 1c f1 [2] 1e f0 [2] 05 f6 [2] 19 f1 [2] 05 de }

  condition:
    any of them
}