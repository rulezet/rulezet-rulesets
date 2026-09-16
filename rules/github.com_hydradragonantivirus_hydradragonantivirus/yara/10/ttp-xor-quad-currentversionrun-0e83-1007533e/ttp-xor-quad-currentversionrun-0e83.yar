rule TTP_XOR_QUAD_CurrentVersionRun_0e83 {
  strings:
    $key_0e83 = { 5d ec [2] 79 e2 [2] 52 ce [2] 7c ec [2] 68 f7 [2] 67 ed [2] 79 f0 [2] 7b f1 [2] 60 f7 [2] 7c f0 [2] 60 df }

  condition:
    any of them
}