rule TTP_XOR_QUAD_CurrentVersionRun_2d83 {
  strings:
    $key_2d83 = { 7e ec [2] 5a e2 [2] 71 ce [2] 5f ec [2] 4b f7 [2] 44 ed [2] 5a f0 [2] 58 f1 [2] 43 f7 [2] 5f f0 [2] 43 df }

  condition:
    any of them
}