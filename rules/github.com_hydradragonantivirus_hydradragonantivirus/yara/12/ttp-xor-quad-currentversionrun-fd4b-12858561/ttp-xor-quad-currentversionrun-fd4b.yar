rule TTP_XOR_QUAD_CurrentVersionRun_fd4b {
  strings:
    $key_fd4b = { ae 24 [2] 8a 2a [2] a1 06 [2] 8f 24 [2] 9b 3f [2] 94 25 [2] 8a 38 [2] 88 39 [2] 93 3f [2] 8f 38 [2] 93 17 }

  condition:
    any of them
}