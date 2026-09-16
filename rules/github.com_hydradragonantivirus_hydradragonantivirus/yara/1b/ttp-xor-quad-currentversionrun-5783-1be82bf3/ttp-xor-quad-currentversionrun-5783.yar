rule TTP_XOR_QUAD_CurrentVersionRun_5783 {
  strings:
    $key_5783 = { 04 ec [2] 20 e2 [2] 0b ce [2] 25 ec [2] 31 f7 [2] 3e ed [2] 20 f0 [2] 22 f1 [2] 39 f7 [2] 25 f0 [2] 39 df }

  condition:
    any of them
}