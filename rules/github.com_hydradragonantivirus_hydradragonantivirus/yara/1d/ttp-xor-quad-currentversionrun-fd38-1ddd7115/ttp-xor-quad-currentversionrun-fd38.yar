rule TTP_XOR_QUAD_CurrentVersionRun_fd38 {
  strings:
    $key_fd38 = { ae 57 [2] 8a 59 [2] a1 75 [2] 8f 57 [2] 9b 4c [2] 94 56 [2] 8a 4b [2] 88 4a [2] 93 4c [2] 8f 4b [2] 93 64 }

  condition:
    any of them
}