rule TTP_XOR_QUAD_CurrentVersionRun_fd83 {
  strings:
    $key_fd83 = { ae ec [2] 8a e2 [2] a1 ce [2] 8f ec [2] 9b f7 [2] 94 ed [2] 8a f0 [2] 88 f1 [2] 93 f7 [2] 8f f0 [2] 93 df }

  condition:
    any of them
}