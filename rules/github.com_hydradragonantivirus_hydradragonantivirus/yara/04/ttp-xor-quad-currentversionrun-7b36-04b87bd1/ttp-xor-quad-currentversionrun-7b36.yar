rule TTP_XOR_QUAD_CurrentVersionRun_7b36 {
  strings:
    $key_7b36 = { 28 59 [2] 0c 57 [2] 27 7b [2] 09 59 [2] 1d 42 [2] 12 58 [2] 0c 45 [2] 0e 44 [2] 15 42 [2] 09 45 [2] 15 6a }

  condition:
    any of them
}