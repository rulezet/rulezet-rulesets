rule TTP_XOR_QUAD_CurrentVersionRun_fd47 {
  strings:
    $key_fd47 = { ae 28 [2] 8a 26 [2] a1 0a [2] 8f 28 [2] 9b 33 [2] 94 29 [2] 8a 34 [2] 88 35 [2] 93 33 [2] 8f 34 [2] 93 1b }

  condition:
    any of them
}