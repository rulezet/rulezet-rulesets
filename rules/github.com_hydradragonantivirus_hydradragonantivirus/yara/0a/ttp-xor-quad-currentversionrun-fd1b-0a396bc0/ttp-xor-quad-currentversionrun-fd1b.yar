rule TTP_XOR_QUAD_CurrentVersionRun_fd1b {
  strings:
    $key_fd1b = { ae 74 [2] 8a 7a [2] a1 56 [2] 8f 74 [2] 9b 6f [2] 94 75 [2] 8a 68 [2] 88 69 [2] 93 6f [2] 8f 68 [2] 93 47 }

  condition:
    any of them
}