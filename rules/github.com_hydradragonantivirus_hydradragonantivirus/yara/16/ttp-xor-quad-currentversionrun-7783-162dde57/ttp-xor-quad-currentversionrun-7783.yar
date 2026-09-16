rule TTP_XOR_QUAD_CurrentVersionRun_7783 {
  strings:
    $key_7783 = { 24 ec [2] 00 e2 [2] 2b ce [2] 05 ec [2] 11 f7 [2] 1e ed [2] 00 f0 [2] 02 f1 [2] 19 f7 [2] 05 f0 [2] 19 df }

  condition:
    any of them
}