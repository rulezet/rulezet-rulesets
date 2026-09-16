rule TTP_XOR_QUAD_CurrentVersionRun_6016 {
  strings:
    $key_6016 = { 33 79 [2] 17 77 [2] 3c 5b [2] 12 79 [2] 06 62 [2] 09 78 [2] 17 65 [2] 15 64 [2] 0e 62 [2] 12 65 [2] 0e 4a }

  condition:
    any of them
}