rule TTP_XOR_QUAD_CurrentVersionRun_2983 {
  strings:
    $key_2983 = { 7a ec [2] 5e e2 [2] 75 ce [2] 5b ec [2] 4f f7 [2] 40 ed [2] 5e f0 [2] 5c f1 [2] 47 f7 [2] 5b f0 [2] 47 df }

  condition:
    any of them
}