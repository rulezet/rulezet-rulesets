rule TTP_XOR_QUAD_CurrentVersionRun_6063 {
  strings:
    $key_6063 = { 33 0c [2] 17 02 [2] 3c 2e [2] 12 0c [2] 06 17 [2] 09 0d [2] 17 10 [2] 15 11 [2] 0e 17 [2] 12 10 [2] 0e 3f }

  condition:
    any of them
}