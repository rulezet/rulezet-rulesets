rule TTP_XOR_QUAD_CurrentVersionRun_fd42 {
  strings:
    $key_fd42 = { ae 2d [2] 8a 23 [2] a1 0f [2] 8f 2d [2] 9b 36 [2] 94 2c [2] 8a 31 [2] 88 30 [2] 93 36 [2] 8f 31 [2] 93 1e }

  condition:
    any of them
}