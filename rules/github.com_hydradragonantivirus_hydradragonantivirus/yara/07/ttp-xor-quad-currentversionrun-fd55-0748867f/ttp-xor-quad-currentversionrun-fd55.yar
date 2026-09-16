rule TTP_XOR_QUAD_CurrentVersionRun_fd55 {
  strings:
    $key_fd55 = { ae 3a [2] 8a 34 [2] a1 18 [2] 8f 3a [2] 9b 21 [2] 94 3b [2] 8a 26 [2] 88 27 [2] 93 21 [2] 8f 26 [2] 93 09 }

  condition:
    any of them
}