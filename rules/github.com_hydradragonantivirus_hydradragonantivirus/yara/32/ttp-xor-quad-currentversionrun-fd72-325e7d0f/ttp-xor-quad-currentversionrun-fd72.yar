rule TTP_XOR_QUAD_CurrentVersionRun_fd72 {
  strings:
    $key_fd72 = { ae 1d [2] 8a 13 [2] a1 3f [2] 8f 1d [2] 9b 06 [2] 94 1c [2] 8a 01 [2] 88 00 [2] 93 06 [2] 8f 01 [2] 93 2e }

  condition:
    any of them
}