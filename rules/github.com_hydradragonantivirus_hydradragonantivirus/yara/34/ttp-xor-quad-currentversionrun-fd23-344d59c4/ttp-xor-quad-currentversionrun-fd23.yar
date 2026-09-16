rule TTP_XOR_QUAD_CurrentVersionRun_fd23 {
  strings:
    $key_fd23 = { ae 4c [2] 8a 42 [2] a1 6e [2] 8f 4c [2] 9b 57 [2] 94 4d [2] 8a 50 [2] 88 51 [2] 93 57 [2] 8f 50 [2] 93 7f }

  condition:
    any of them
}