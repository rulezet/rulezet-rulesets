rule TTP_XOR_QUAD_CurrentVersionRun_4298 {
  strings:
    $key_4298 = { 11 f7 [2] 35 f9 [2] 1e d5 [2] 30 f7 [2] 24 ec [2] 2b f6 [2] 35 eb [2] 37 ea [2] 2c ec [2] 30 eb [2] 2c c4 }

  condition:
    any of them
}