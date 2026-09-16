rule TTP_XOR_QUAD_CurrentVersionRun_fd65 {
  strings:
    $key_fd65 = { ae 0a [2] 8a 04 [2] a1 28 [2] 8f 0a [2] 9b 11 [2] 94 0b [2] 8a 16 [2] 88 17 [2] 93 11 [2] 8f 16 [2] 93 39 }

  condition:
    any of them
}