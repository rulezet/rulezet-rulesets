rule TTP_XOR_QUAD_CurrentVersionRun_fd2f {
  strings:
    $key_fd2f = { ae 40 [2] 8a 4e [2] a1 62 [2] 8f 40 [2] 9b 5b [2] 94 41 [2] 8a 5c [2] 88 5d [2] 93 5b [2] 8f 5c [2] 93 73 }

  condition:
    any of them
}