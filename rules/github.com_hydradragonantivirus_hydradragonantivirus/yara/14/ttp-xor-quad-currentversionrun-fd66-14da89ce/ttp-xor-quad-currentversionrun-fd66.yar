rule TTP_XOR_QUAD_CurrentVersionRun_fd66 {
  strings:
    $key_fd66 = { ae 09 [2] 8a 07 [2] a1 2b [2] 8f 09 [2] 9b 12 [2] 94 08 [2] 8a 15 [2] 88 14 [2] 93 12 [2] 8f 15 [2] 93 3a }

  condition:
    any of them
}