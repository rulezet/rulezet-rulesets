rule TTP_XOR_QUAD_CurrentVersionRun_6863 {
  strings:
    $key_6863 = { 3b 0c [2] 1f 02 [2] 34 2e [2] 1a 0c [2] 0e 17 [2] 01 0d [2] 1f 10 [2] 1d 11 [2] 06 17 [2] 1a 10 [2] 06 3f }

  condition:
    any of them
}