rule TTP_XOR_QUAD_CurrentVersionRun_7a82 {
  strings:
    $key_7a82 = { 29 ed [2] 0d e3 [2] 26 cf [2] 08 ed [2] 1c f6 [2] 13 ec [2] 0d f1 [2] 0f f0 [2] 14 f6 [2] 08 f1 [2] 14 de }

  condition:
    any of them
}