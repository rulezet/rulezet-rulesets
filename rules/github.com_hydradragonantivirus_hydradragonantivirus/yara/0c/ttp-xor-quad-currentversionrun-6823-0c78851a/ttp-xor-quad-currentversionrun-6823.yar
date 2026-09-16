rule TTP_XOR_QUAD_CurrentVersionRun_6823 {
  strings:
    $key_6823 = { 3b 4c [2] 1f 42 [2] 34 6e [2] 1a 4c [2] 0e 57 [2] 01 4d [2] 1f 50 [2] 1d 51 [2] 06 57 [2] 1a 50 [2] 06 7f }

  condition:
    any of them
}