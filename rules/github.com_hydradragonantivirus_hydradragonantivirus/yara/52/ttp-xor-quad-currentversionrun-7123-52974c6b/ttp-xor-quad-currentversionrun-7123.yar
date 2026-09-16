rule TTP_XOR_QUAD_CurrentVersionRun_7123 {
  strings:
    $key_7123 = { 22 4c [2] 06 42 [2] 2d 6e [2] 03 4c [2] 17 57 [2] 18 4d [2] 06 50 [2] 04 51 [2] 1f 57 [2] 03 50 [2] 1f 7f }

  condition:
    any of them
}