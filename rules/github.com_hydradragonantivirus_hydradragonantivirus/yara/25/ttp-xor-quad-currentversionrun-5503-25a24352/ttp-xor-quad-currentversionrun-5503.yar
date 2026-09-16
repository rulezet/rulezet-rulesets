rule TTP_XOR_QUAD_CurrentVersionRun_5503 {
  strings:
    $key_5503 = { 06 6c [2] 22 62 [2] 09 4e [2] 27 6c [2] 33 77 [2] 3c 6d [2] 22 70 [2] 20 71 [2] 3b 77 [2] 27 70 [2] 3b 5f }

  condition:
    any of them
}