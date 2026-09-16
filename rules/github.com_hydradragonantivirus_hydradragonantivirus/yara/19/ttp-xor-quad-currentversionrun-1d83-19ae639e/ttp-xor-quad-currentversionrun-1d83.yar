rule TTP_XOR_QUAD_CurrentVersionRun_1d83 {
  strings:
    $key_1d83 = { 4e ec [2] 6a e2 [2] 41 ce [2] 6f ec [2] 7b f7 [2] 74 ed [2] 6a f0 [2] 68 f1 [2] 73 f7 [2] 6f f0 [2] 73 df }

  condition:
    any of them
}