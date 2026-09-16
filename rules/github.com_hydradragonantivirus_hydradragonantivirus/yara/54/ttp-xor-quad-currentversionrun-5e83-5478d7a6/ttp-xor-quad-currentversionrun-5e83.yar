rule TTP_XOR_QUAD_CurrentVersionRun_5e83 {
  strings:
    $key_5e83 = { 0d ec [2] 29 e2 [2] 02 ce [2] 2c ec [2] 38 f7 [2] 37 ed [2] 29 f0 [2] 2b f1 [2] 30 f7 [2] 2c f0 [2] 30 df }

  condition:
    any of them
}