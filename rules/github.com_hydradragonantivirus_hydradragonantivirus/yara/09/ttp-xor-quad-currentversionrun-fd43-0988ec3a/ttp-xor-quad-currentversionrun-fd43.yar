rule TTP_XOR_QUAD_CurrentVersionRun_fd43 {
  strings:
    $key_fd43 = { ae 2c [2] 8a 22 [2] a1 0e [2] 8f 2c [2] 9b 37 [2] 94 2d [2] 8a 30 [2] 88 31 [2] 93 37 [2] 8f 30 [2] 93 1f }

  condition:
    any of them
}