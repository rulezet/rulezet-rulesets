rule TTP_XOR_QUAD_CurrentVersionRun_fd79 {
  strings:
    $key_fd79 = { ae 16 [2] 8a 18 [2] a1 34 [2] 8f 16 [2] 9b 0d [2] 94 17 [2] 8a 0a [2] 88 0b [2] 93 0d [2] 8f 0a [2] 93 25 }

  condition:
    any of them
}