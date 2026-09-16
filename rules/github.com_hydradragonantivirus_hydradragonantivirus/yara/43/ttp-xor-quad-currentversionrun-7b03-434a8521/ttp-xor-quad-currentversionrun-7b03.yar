rule TTP_XOR_QUAD_CurrentVersionRun_7b03 {
  strings:
    $key_7b03 = { 28 6c [2] 0c 62 [2] 27 4e [2] 09 6c [2] 1d 77 [2] 12 6d [2] 0c 70 [2] 0e 71 [2] 15 77 [2] 09 70 [2] 15 5f }

  condition:
    any of them
}