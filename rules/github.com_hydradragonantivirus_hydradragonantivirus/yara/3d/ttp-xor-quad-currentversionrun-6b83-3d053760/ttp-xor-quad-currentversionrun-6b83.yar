rule TTP_XOR_QUAD_CurrentVersionRun_6b83 {
  strings:
    $key_6b83 = { 38 ec [2] 1c e2 [2] 37 ce [2] 19 ec [2] 0d f7 [2] 02 ed [2] 1c f0 [2] 1e f1 [2] 05 f7 [2] 19 f0 [2] 05 df }

  condition:
    any of them
}