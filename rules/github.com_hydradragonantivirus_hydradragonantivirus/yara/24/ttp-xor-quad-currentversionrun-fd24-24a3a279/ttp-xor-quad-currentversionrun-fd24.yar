rule TTP_XOR_QUAD_CurrentVersionRun_fd24 {
  strings:
    $key_fd24 = { ae 4b [2] 8a 45 [2] a1 69 [2] 8f 4b [2] 9b 50 [2] 94 4a [2] 8a 57 [2] 88 56 [2] 93 50 [2] 8f 57 [2] 93 78 }

  condition:
    any of them
}