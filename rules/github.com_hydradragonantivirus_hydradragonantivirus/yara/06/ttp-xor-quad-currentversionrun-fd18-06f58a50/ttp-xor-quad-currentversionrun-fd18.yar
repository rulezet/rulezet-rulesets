rule TTP_XOR_QUAD_CurrentVersionRun_fd18 {
  strings:
    $key_fd18 = { ae 77 [2] 8a 79 [2] a1 55 [2] 8f 77 [2] 9b 6c [2] 94 76 [2] 8a 6b [2] 88 6a [2] 93 6c [2] 8f 6b [2] 93 44 }

  condition:
    any of them
}