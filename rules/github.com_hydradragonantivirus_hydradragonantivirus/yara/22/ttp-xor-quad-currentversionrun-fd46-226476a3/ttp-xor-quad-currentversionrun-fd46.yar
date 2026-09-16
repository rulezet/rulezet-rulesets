rule TTP_XOR_QUAD_CurrentVersionRun_fd46 {
  strings:
    $key_fd46 = { ae 29 [2] 8a 27 [2] a1 0b [2] 8f 29 [2] 9b 32 [2] 94 28 [2] 8a 35 [2] 88 34 [2] 93 32 [2] 8f 35 [2] 93 1a }

  condition:
    any of them
}