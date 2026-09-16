rule TTP_XOR_QUAD_CurrentVersionRun_4963 {
  strings:
    $key_4963 = { 1a 0c [2] 3e 02 [2] 15 2e [2] 3b 0c [2] 2f 17 [2] 20 0d [2] 3e 10 [2] 3c 11 [2] 27 17 [2] 3b 10 [2] 27 3f }

  condition:
    any of them
}