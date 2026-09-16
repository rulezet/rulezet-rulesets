rule TTP_XOR_QUAD_CurrentVersionRun_fd4e {
  strings:
    $key_fd4e = { ae 21 [2] 8a 2f [2] a1 03 [2] 8f 21 [2] 9b 3a [2] 94 20 [2] 8a 3d [2] 88 3c [2] 93 3a [2] 8f 3d [2] 93 12 }

  condition:
    any of them
}