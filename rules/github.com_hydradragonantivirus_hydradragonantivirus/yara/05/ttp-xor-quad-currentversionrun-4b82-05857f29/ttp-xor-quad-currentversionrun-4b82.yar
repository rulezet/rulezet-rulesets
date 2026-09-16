rule TTP_XOR_QUAD_CurrentVersionRun_4b82 {
  strings:
    $key_4b82 = { 18 ed [2] 3c e3 [2] 17 cf [2] 39 ed [2] 2d f6 [2] 22 ec [2] 3c f1 [2] 3e f0 [2] 25 f6 [2] 39 f1 [2] 25 de }

  condition:
    any of them
}