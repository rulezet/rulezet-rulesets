rule TTP_XOR_QUAD_CurrentVersionRun_fd1c {
  strings:
    $key_fd1c = { ae 73 [2] 8a 7d [2] a1 51 [2] 8f 73 [2] 9b 68 [2] 94 72 [2] 8a 6f [2] 88 6e [2] 93 68 [2] 8f 6f [2] 93 40 }

  condition:
    any of them
}