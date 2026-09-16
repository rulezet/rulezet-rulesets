rule TTP_XOR_QUAD_CurrentVersionRun_fd25 {
  strings:
    $key_fd25 = { ae 4a [2] 8a 44 [2] a1 68 [2] 8f 4a [2] 9b 51 [2] 94 4b [2] 8a 56 [2] 88 57 [2] 93 51 [2] 8f 56 [2] 93 79 }

  condition:
    any of them
}