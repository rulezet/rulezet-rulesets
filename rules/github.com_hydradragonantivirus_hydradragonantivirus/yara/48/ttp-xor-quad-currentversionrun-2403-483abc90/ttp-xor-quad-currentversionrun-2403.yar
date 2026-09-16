rule TTP_XOR_QUAD_CurrentVersionRun_2403 {
  strings:
    $key_2403 = { 77 6c [2] 53 62 [2] 78 4e [2] 56 6c [2] 42 77 [2] 4d 6d [2] 53 70 [2] 51 71 [2] 4a 77 [2] 56 70 [2] 4a 5f }

  condition:
    any of them
}