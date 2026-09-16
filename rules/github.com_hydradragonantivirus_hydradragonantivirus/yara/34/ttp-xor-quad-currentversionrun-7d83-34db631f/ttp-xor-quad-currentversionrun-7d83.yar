rule TTP_XOR_QUAD_CurrentVersionRun_7d83 {
  strings:
    $key_7d83 = { 2e ec [2] 0a e2 [2] 21 ce [2] 0f ec [2] 1b f7 [2] 14 ed [2] 0a f0 [2] 08 f1 [2] 13 f7 [2] 0f f0 [2] 13 df }

  condition:
    any of them
}