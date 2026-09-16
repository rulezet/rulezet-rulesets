rule TTP_XOR_QUAD_CurrentVersionRun_1e82 {
  strings:
    $key_1e82 = { 4d ed [2] 69 e3 [2] 42 cf [2] 6c ed [2] 78 f6 [2] 77 ec [2] 69 f1 [2] 6b f0 [2] 70 f6 [2] 6c f1 [2] 70 de }

  condition:
    any of them
}