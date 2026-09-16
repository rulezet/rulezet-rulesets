rule TTP_XOR_QUAD_CurrentVersionRun_fd4c {
  strings:
    $key_fd4c = { ae 23 [2] 8a 2d [2] a1 01 [2] 8f 23 [2] 9b 38 [2] 94 22 [2] 8a 3f [2] 88 3e [2] 93 38 [2] 8f 3f [2] 93 10 }

  condition:
    any of them
}