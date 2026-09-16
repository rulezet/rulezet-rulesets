rule TTP_XOR_QUAD_CurrentVersionRun_3982 {
  strings:
    $key_3982 = { 6a ed [2] 4e e3 [2] 65 cf [2] 4b ed [2] 5f f6 [2] 50 ec [2] 4e f1 [2] 4c f0 [2] 57 f6 [2] 4b f1 [2] 57 de }

  condition:
    any of them
}