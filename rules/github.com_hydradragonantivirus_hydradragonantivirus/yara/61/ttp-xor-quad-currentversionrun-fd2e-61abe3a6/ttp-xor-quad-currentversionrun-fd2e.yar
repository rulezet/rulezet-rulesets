rule TTP_XOR_QUAD_CurrentVersionRun_fd2e {
  strings:
    $key_fd2e = { ae 41 [2] 8a 4f [2] a1 63 [2] 8f 41 [2] 9b 5a [2] 94 40 [2] 8a 5d [2] 88 5c [2] 93 5a [2] 8f 5d [2] 93 72 }

  condition:
    any of them
}