rule TTP_XOR_QUAD_CurrentVersionRun_0c83 {
  strings:
    $key_0c83 = { 5f ec [2] 7b e2 [2] 50 ce [2] 7e ec [2] 6a f7 [2] 65 ed [2] 7b f0 [2] 79 f1 [2] 62 f7 [2] 7e f0 [2] 62 df }

  condition:
    any of them
}