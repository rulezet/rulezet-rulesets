rule TTP_XOR_QUAD_CurrentVersionRun_1a83 {
  strings:
    $key_1a83 = { 49 ec [2] 6d e2 [2] 46 ce [2] 68 ec [2] 7c f7 [2] 73 ed [2] 6d f0 [2] 6f f1 [2] 74 f7 [2] 68 f0 [2] 74 df }

  condition:
    any of them
}