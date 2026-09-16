rule TTP_XOR_QUAD_CurrentVersionRun_e983 {
  strings:
    $key_e983 = { ba ec [2] 9e e2 [2] b5 ce [2] 9b ec [2] 8f f7 [2] 80 ed [2] 9e f0 [2] 9c f1 [2] 87 f7 [2] 9b f0 [2] 87 df }

  condition:
    any of them
}