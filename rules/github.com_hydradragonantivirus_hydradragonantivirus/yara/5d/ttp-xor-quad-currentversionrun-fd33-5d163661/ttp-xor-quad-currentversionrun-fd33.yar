rule TTP_XOR_QUAD_CurrentVersionRun_fd33 {
  strings:
    $key_fd33 = { ae 5c [2] 8a 52 [2] a1 7e [2] 8f 5c [2] 9b 47 [2] 94 5d [2] 8a 40 [2] 88 41 [2] 93 47 [2] 8f 40 [2] 93 6f }

  condition:
    any of them
}