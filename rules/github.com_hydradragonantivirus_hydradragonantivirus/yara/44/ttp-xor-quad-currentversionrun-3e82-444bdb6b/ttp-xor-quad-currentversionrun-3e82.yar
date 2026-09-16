rule TTP_XOR_QUAD_CurrentVersionRun_3e82 {
  strings:
    $key_3e82 = { 6d ed [2] 49 e3 [2] 62 cf [2] 4c ed [2] 58 f6 [2] 57 ec [2] 49 f1 [2] 4b f0 [2] 50 f6 [2] 4c f1 [2] 50 de }

  condition:
    any of them
}