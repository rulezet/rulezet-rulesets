rule TTP_XOR_QUAD_CurrentVersionRun_1e83 {
  strings:
    $key_1e83 = { 4d ec [2] 69 e2 [2] 42 ce [2] 6c ec [2] 78 f7 [2] 77 ed [2] 69 f0 [2] 6b f1 [2] 70 f7 [2] 6c f0 [2] 70 df }

  condition:
    any of them
}