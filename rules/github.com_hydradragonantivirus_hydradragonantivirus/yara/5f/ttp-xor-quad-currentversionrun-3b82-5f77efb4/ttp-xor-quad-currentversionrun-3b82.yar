rule TTP_XOR_QUAD_CurrentVersionRun_3b82 {
  strings:
    $key_3b82 = { 68 ed [2] 4c e3 [2] 67 cf [2] 49 ed [2] 5d f6 [2] 52 ec [2] 4c f1 [2] 4e f0 [2] 55 f6 [2] 49 f1 [2] 55 de }

  condition:
    any of them
}