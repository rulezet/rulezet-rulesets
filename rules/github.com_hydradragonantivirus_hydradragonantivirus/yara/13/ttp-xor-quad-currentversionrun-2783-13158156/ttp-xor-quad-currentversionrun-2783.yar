rule TTP_XOR_QUAD_CurrentVersionRun_2783 {
  strings:
    $key_2783 = { 74 ec [2] 50 e2 [2] 7b ce [2] 55 ec [2] 41 f7 [2] 4e ed [2] 50 f0 [2] 52 f1 [2] 49 f7 [2] 55 f0 [2] 49 df }

  condition:
    any of them
}