rule TTP_XOR_QUAD_CurrentVersionRun_3783 {
  strings:
    $key_3783 = { 64 ec [2] 40 e2 [2] 6b ce [2] 45 ec [2] 51 f7 [2] 5e ed [2] 40 f0 [2] 42 f1 [2] 59 f7 [2] 45 f0 [2] 59 df }

  condition:
    any of them
}