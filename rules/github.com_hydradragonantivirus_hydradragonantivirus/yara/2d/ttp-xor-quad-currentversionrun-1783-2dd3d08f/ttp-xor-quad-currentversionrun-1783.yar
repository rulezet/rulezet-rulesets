rule TTP_XOR_QUAD_CurrentVersionRun_1783 {
  strings:
    $key_1783 = { 44 ec [2] 60 e2 [2] 4b ce [2] 65 ec [2] 71 f7 [2] 7e ed [2] 60 f0 [2] 62 f1 [2] 79 f7 [2] 65 f0 [2] 79 df }

  condition:
    any of them
}