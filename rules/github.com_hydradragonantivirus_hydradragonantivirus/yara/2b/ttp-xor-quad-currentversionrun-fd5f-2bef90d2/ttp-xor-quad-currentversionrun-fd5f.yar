rule TTP_XOR_QUAD_CurrentVersionRun_fd5f {
  strings:
    $key_fd5f = { ae 30 [2] 8a 3e [2] a1 12 [2] 8f 30 [2] 9b 2b [2] 94 31 [2] 8a 2c [2] 88 2d [2] 93 2b [2] 8f 2c [2] 93 03 }

  condition:
    any of them
}