rule TTP_XOR_QUAD_CurrentVersionRun_7b83 {
  strings:
    $key_7b83 = { 28 ec [2] 0c e2 [2] 27 ce [2] 09 ec [2] 1d f7 [2] 12 ed [2] 0c f0 [2] 0e f1 [2] 15 f7 [2] 09 f0 [2] 15 df }

  condition:
    any of them
}