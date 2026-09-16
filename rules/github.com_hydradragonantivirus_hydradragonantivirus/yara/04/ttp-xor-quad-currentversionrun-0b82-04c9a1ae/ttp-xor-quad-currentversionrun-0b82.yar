rule TTP_XOR_QUAD_CurrentVersionRun_0b82 {
  strings:
    $key_0b82 = { 58 ed [2] 7c e3 [2] 57 cf [2] 79 ed [2] 6d f6 [2] 62 ec [2] 7c f1 [2] 7e f0 [2] 65 f6 [2] 79 f1 [2] 65 de }

  condition:
    any of them
}