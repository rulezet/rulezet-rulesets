rule TTP_XOR_QUAD_CurrentVersionRun_fd52 {
  strings:
    $key_fd52 = { ae 3d [2] 8a 33 [2] a1 1f [2] 8f 3d [2] 9b 26 [2] 94 3c [2] 8a 21 [2] 88 20 [2] 93 26 [2] 8f 21 [2] 93 0e }

  condition:
    any of them
}