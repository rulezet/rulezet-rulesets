rule TTP_XOR_QUAD_CurrentVersionRun_0463 {
  strings:
    $key_0463 = { 57 0c [2] 73 02 [2] 58 2e [2] 76 0c [2] 62 17 [2] 6d 0d [2] 73 10 [2] 71 11 [2] 6a 17 [2] 76 10 [2] 6a 3f }

  condition:
    any of them
}