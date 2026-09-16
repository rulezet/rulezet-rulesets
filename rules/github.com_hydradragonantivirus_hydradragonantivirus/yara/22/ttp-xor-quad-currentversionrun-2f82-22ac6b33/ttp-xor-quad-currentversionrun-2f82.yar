rule TTP_XOR_QUAD_CurrentVersionRun_2f82 {
  strings:
    $key_2f82 = { 7c ed [2] 58 e3 [2] 73 cf [2] 5d ed [2] 49 f6 [2] 46 ec [2] 58 f1 [2] 5a f0 [2] 41 f6 [2] 5d f1 [2] 41 de }

  condition:
    any of them
}