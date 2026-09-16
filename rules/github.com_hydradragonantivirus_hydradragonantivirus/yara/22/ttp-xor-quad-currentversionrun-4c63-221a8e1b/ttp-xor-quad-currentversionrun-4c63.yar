rule TTP_XOR_QUAD_CurrentVersionRun_4c63 {
  strings:
    $key_4c63 = { 1f 0c [2] 3b 02 [2] 10 2e [2] 3e 0c [2] 2a 17 [2] 25 0d [2] 3b 10 [2] 39 11 [2] 22 17 [2] 3e 10 [2] 22 3f }

  condition:
    any of them
}