rule TTP_XOR_QUAD_CurrentVersionRun_ea82 {
  strings:
    $key_ea82 = { b9 ed [2] 9d e3 [2] b6 cf [2] 98 ed [2] 8c f6 [2] 83 ec [2] 9d f1 [2] 9f f0 [2] 84 f6 [2] 98 f1 [2] 84 de }

  condition:
    any of them
}