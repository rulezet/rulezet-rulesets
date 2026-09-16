rule TTP_XOR_QUAD_CurrentVersionRun_0783 {
  strings:
    $key_0783 = { 54 ec [2] 70 e2 [2] 5b ce [2] 75 ec [2] 61 f7 [2] 6e ed [2] 70 f0 [2] 72 f1 [2] 69 f7 [2] 75 f0 [2] 69 df }

  condition:
    any of them
}