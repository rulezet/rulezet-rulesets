rule TTP_XOR_QUAD_CurrentVersionRun_fd49 {
  strings:
    $key_fd49 = { ae 26 [2] 8a 28 [2] a1 04 [2] 8f 26 [2] 9b 3d [2] 94 27 [2] 8a 3a [2] 88 3b [2] 93 3d [2] 8f 3a [2] 93 15 }

  condition:
    any of them
}