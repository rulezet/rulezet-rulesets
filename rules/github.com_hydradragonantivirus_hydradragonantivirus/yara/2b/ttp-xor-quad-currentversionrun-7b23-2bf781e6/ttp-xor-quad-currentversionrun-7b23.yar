rule TTP_XOR_QUAD_CurrentVersionRun_7b23 {
  strings:
    $key_7b23 = { 28 4c [2] 0c 42 [2] 27 6e [2] 09 4c [2] 1d 57 [2] 12 4d [2] 0c 50 [2] 0e 51 [2] 15 57 [2] 09 50 [2] 15 7f }

  condition:
    any of them
}