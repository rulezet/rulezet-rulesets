rule TTP_XOR_QUAD_CurrentVersionRun_0983 {
  strings:
    $key_0983 = { 5a ec [2] 7e e2 [2] 55 ce [2] 7b ec [2] 6f f7 [2] 60 ed [2] 7e f0 [2] 7c f1 [2] 67 f7 [2] 7b f0 [2] 67 df }

  condition:
    any of them
}