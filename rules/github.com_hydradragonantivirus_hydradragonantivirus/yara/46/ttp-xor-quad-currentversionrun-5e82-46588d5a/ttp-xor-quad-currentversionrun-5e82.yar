rule TTP_XOR_QUAD_CurrentVersionRun_5e82 {
  strings:
    $key_5e82 = { 0d ed [2] 29 e3 [2] 02 cf [2] 2c ed [2] 38 f6 [2] 37 ec [2] 29 f1 [2] 2b f0 [2] 30 f6 [2] 2c f1 [2] 30 de }

  condition:
    any of them
}