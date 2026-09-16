rule TTP_XOR_QUAD_CurrentVersionRun_fc83 {
  strings:
    $key_fc83 = { af ec [2] 8b e2 [2] a0 ce [2] 8e ec [2] 9a f7 [2] 95 ed [2] 8b f0 [2] 89 f1 [2] 92 f7 [2] 8e f0 [2] 92 df }

  condition:
    any of them
}