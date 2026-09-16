rule TTP_XOR_QUAD_CurrentVersionRun_fd6f {
  strings:
    $key_fd6f = { ae 00 [2] 8a 0e [2] a1 22 [2] 8f 00 [2] 9b 1b [2] 94 01 [2] 8a 1c [2] 88 1d [2] 93 1b [2] 8f 1c [2] 93 33 }

  condition:
    any of them
}