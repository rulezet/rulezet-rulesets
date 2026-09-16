rule TTP_XOR_QUAD_CurrentVersionRun_0363 {
  strings:
    $key_0363 = { 50 0c [2] 74 02 [2] 5f 2e [2] 71 0c [2] 65 17 [2] 6a 0d [2] 74 10 [2] 76 11 [2] 6d 17 [2] 71 10 [2] 6d 3f }

  condition:
    any of them
}