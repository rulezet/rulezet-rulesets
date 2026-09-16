rule TTP_XOR_QUAD_CurrentVersionRun_fd57 {
  strings:
    $key_fd57 = { ae 38 [2] 8a 36 [2] a1 1a [2] 8f 38 [2] 9b 23 [2] 94 39 [2] 8a 24 [2] 88 25 [2] 93 23 [2] 8f 24 [2] 93 0b }

  condition:
    any of them
}