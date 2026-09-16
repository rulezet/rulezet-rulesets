rule TTP_XOR_QUAD_CurrentVersionRun_7c83 {
  strings:
    $key_7c83 = { 2f ec [2] 0b e2 [2] 20 ce [2] 0e ec [2] 1a f7 [2] 15 ed [2] 0b f0 [2] 09 f1 [2] 12 f7 [2] 0e f0 [2] 12 df }

  condition:
    any of them
}