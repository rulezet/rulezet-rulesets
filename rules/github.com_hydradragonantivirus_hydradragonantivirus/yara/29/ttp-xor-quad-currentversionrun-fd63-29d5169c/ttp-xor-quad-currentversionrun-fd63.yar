rule TTP_XOR_QUAD_CurrentVersionRun_fd63 {
  strings:
    $key_fd63 = { ae 0c [2] 8a 02 [2] a1 2e [2] 8f 0c [2] 9b 17 [2] 94 0d [2] 8a 10 [2] 88 11 [2] 93 17 [2] 8f 10 [2] 93 3f }

  condition:
    any of them
}