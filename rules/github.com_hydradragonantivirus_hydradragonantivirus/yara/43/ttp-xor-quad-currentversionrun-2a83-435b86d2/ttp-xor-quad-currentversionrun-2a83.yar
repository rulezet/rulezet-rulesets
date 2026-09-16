rule TTP_XOR_QUAD_CurrentVersionRun_2a83 {
  strings:
    $key_2a83 = { 79 ec [2] 5d e2 [2] 76 ce [2] 58 ec [2] 4c f7 [2] 43 ed [2] 5d f0 [2] 5f f1 [2] 44 f7 [2] 58 f0 [2] 44 df }

  condition:
    any of them
}