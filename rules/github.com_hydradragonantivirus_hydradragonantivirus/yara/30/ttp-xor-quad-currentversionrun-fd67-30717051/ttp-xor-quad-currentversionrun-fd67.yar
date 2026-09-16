rule TTP_XOR_QUAD_CurrentVersionRun_fd67 {
  strings:
    $key_fd67 = { ae 08 [2] 8a 06 [2] a1 2a [2] 8f 08 [2] 9b 13 [2] 94 09 [2] 8a 14 [2] 88 15 [2] 93 13 [2] 8f 14 [2] 93 3b }

  condition:
    any of them
}