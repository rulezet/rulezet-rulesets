rule TTP_XOR_QUAD_CurrentVersionRun_1982 {
  strings:
    $key_1982 = { 4a ed [2] 6e e3 [2] 45 cf [2] 6b ed [2] 7f f6 [2] 70 ec [2] 6e f1 [2] 6c f0 [2] 77 f6 [2] 6b f1 [2] 77 de }

  condition:
    any of them
}