rule TTP_XOR_QUAD_CurrentVersionRun_fd39 {
  strings:
    $key_fd39 = { ae 56 [2] 8a 58 [2] a1 74 [2] 8f 56 [2] 9b 4d [2] 94 57 [2] 8a 4a [2] 88 4b [2] 93 4d [2] 8f 4a [2] 93 65 }

  condition:
    any of them
}