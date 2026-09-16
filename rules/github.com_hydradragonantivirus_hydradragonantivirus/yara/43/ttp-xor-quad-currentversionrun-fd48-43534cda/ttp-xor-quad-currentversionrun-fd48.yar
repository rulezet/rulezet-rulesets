rule TTP_XOR_QUAD_CurrentVersionRun_fd48 {
  strings:
    $key_fd48 = { ae 27 [2] 8a 29 [2] a1 05 [2] 8f 27 [2] 9b 3c [2] 94 26 [2] 8a 3b [2] 88 3a [2] 93 3c [2] 8f 3b [2] 93 14 }

  condition:
    any of them
}