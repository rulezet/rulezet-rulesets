rule TTP_XOR_QUAD_CurrentVersionRun_fd44 {
  strings:
    $key_fd44 = { ae 2b [2] 8a 25 [2] a1 09 [2] 8f 2b [2] 9b 30 [2] 94 2a [2] 8a 37 [2] 88 36 [2] 93 30 [2] 8f 37 [2] 93 18 }

  condition:
    any of them
}