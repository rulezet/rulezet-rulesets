rule TTP_XOR_QUAD_CurrentVersionRun_5f03 {
  strings:
    $key_5f03 = { 0c 6c [2] 28 62 [2] 03 4e [2] 2d 6c [2] 39 77 [2] 36 6d [2] 28 70 [2] 2a 71 [2] 31 77 [2] 2d 70 [2] 31 5f }

  condition:
    any of them
}