rule TTP_XOR_QUAD_CurrentVersionRun_fd61 {
  strings:
    $key_fd61 = { ae 0e [2] 8a 00 [2] a1 2c [2] 8f 0e [2] 9b 15 [2] 94 0f [2] 8a 12 [2] 88 13 [2] 93 15 [2] 8f 12 [2] 93 3d }

  condition:
    any of them
}