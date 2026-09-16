rule TTP_XOR_QUAD_CurrentVersionRun_5a83 {
  strings:
    $key_5a83 = { 09 ec [2] 2d e2 [2] 06 ce [2] 28 ec [2] 3c f7 [2] 33 ed [2] 2d f0 [2] 2f f1 [2] 34 f7 [2] 28 f0 [2] 34 df }

  condition:
    any of them
}