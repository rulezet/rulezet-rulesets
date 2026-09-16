rule TTP_XOR_QUAD_CurrentVersionRun_fd7d {
  strings:
    $key_fd7d = { ae 12 [2] 8a 1c [2] a1 30 [2] 8f 12 [2] 9b 09 [2] 94 13 [2] 8a 0e [2] 88 0f [2] 93 09 [2] 8f 0e [2] 93 21 }

  condition:
    any of them
}