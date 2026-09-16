rule TTP_XOR_QUAD_CurrentVersionRun_fd0b {
  strings:
    $key_fd0b = { ae 64 [2] 8a 6a [2] a1 46 [2] 8f 64 [2] 9b 7f [2] 94 65 [2] 8a 78 [2] 88 79 [2] 93 7f [2] 8f 78 [2] 93 57 }

  condition:
    any of them
}