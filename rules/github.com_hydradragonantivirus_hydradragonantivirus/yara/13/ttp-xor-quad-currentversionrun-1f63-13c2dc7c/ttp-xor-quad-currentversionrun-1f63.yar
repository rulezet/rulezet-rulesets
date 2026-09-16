rule TTP_XOR_QUAD_CurrentVersionRun_1f63 {
  strings:
    $key_1f63 = { 4c 0c [2] 68 02 [2] 43 2e [2] 6d 0c [2] 79 17 [2] 76 0d [2] 68 10 [2] 6a 11 [2] 71 17 [2] 6d 10 [2] 71 3f }

  condition:
    any of them
}