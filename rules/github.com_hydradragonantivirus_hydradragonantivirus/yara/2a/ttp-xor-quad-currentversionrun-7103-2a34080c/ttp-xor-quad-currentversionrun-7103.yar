rule TTP_XOR_QUAD_CurrentVersionRun_7103 {
  strings:
    $key_7103 = { 22 6c [2] 06 62 [2] 2d 4e [2] 03 6c [2] 17 77 [2] 18 6d [2] 06 70 [2] 04 71 [2] 1f 77 [2] 03 70 [2] 1f 5f }

  condition:
    any of them
}