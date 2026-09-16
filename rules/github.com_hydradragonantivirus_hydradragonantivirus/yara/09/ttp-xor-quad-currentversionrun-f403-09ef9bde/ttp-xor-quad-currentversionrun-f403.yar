rule TTP_XOR_QUAD_CurrentVersionRun_f403 {
  strings:
    $key_f403 = { a7 6c [2] 83 62 [2] a8 4e [2] 86 6c [2] 92 77 [2] 9d 6d [2] 83 70 [2] 81 71 [2] 9a 77 [2] 86 70 [2] 9a 5f }

  condition:
    any of them
}