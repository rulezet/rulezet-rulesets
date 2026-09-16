rule TTP_XOR_QUAD_CurrentVersionRun_5a23 {
  strings:
    $key_5a23 = { 09 4c [2] 2d 42 [2] 06 6e [2] 28 4c [2] 3c 57 [2] 33 4d [2] 2d 50 [2] 2f 51 [2] 34 57 [2] 28 50 [2] 34 7f }

  condition:
    any of them
}