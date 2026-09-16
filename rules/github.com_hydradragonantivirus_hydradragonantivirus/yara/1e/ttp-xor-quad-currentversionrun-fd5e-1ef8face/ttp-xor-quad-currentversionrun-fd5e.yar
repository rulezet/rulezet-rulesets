rule TTP_XOR_QUAD_CurrentVersionRun_fd5e {
  strings:
    $key_fd5e = { ae 31 [2] 8a 3f [2] a1 13 [2] 8f 31 [2] 9b 2a [2] 94 30 [2] 8a 2d [2] 88 2c [2] 93 2a [2] 8f 2d [2] 93 02 }

  condition:
    any of them
}