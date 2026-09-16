rule TTP_XOR_QUAD_CurrentVersionRun_fd1d {
  strings:
    $key_fd1d = { ae 72 [2] 8a 7c [2] a1 50 [2] 8f 72 [2] 9b 69 [2] 94 73 [2] 8a 6e [2] 88 6f [2] 93 69 [2] 8f 6e [2] 93 41 }

  condition:
    any of them
}