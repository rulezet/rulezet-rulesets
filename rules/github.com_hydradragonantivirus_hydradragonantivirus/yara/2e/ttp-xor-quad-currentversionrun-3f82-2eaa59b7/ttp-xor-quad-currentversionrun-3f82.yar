rule TTP_XOR_QUAD_CurrentVersionRun_3f82 {
  strings:
    $key_3f82 = { 6c ed [2] 48 e3 [2] 63 cf [2] 4d ed [2] 59 f6 [2] 56 ec [2] 48 f1 [2] 4a f0 [2] 51 f6 [2] 4d f1 [2] 51 de }

  condition:
    any of them
}