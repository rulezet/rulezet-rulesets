rule TTP_XOR_QUAD_CurrentVersionRun_5982 {
  strings:
    $key_5982 = { 0a ed [2] 2e e3 [2] 05 cf [2] 2b ed [2] 3f f6 [2] 30 ec [2] 2e f1 [2] 2c f0 [2] 37 f6 [2] 2b f1 [2] 37 de }

  condition:
    any of them
}