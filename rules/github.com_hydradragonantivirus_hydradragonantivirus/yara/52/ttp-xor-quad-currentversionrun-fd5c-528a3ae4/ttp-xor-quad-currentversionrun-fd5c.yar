rule TTP_XOR_QUAD_CurrentVersionRun_fd5c {
  strings:
    $key_fd5c = { ae 33 [2] 8a 3d [2] a1 11 [2] 8f 33 [2] 9b 28 [2] 94 32 [2] 8a 2f [2] 88 2e [2] 93 28 [2] 8f 2f [2] 93 00 }

  condition:
    any of them
}