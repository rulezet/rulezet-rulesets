rule TTP_XOR_QUAD_CurrentVersionRun_4803 {
  strings:
    $key_4803 = { 1b 6c [2] 3f 62 [2] 14 4e [2] 3a 6c [2] 2e 77 [2] 21 6d [2] 3f 70 [2] 3d 71 [2] 26 77 [2] 3a 70 [2] 26 5f }

  condition:
    any of them
}