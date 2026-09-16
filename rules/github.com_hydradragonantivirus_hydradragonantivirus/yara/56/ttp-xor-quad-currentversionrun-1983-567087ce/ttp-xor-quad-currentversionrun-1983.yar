rule TTP_XOR_QUAD_CurrentVersionRun_1983 {
  strings:
    $key_1983 = { 4a ec [2] 6e e2 [2] 45 ce [2] 6b ec [2] 7f f7 [2] 70 ed [2] 6e f0 [2] 6c f1 [2] 77 f7 [2] 6b f0 [2] 77 df }

  condition:
    any of them
}