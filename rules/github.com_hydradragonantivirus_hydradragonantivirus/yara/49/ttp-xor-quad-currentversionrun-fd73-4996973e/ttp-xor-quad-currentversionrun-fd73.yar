rule TTP_XOR_QUAD_CurrentVersionRun_fd73 {
  strings:
    $key_fd73 = { ae 1c [2] 8a 12 [2] a1 3e [2] 8f 1c [2] 9b 07 [2] 94 1d [2] 8a 00 [2] 88 01 [2] 93 07 [2] 8f 00 [2] 93 2f }

  condition:
    any of them
}