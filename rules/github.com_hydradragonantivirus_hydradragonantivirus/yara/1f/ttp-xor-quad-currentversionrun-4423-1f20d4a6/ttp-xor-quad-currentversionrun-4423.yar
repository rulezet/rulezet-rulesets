rule TTP_XOR_QUAD_CurrentVersionRun_4423 {
  strings:
    $key_4423 = { 17 4c [2] 33 42 [2] 18 6e [2] 36 4c [2] 22 57 [2] 2d 4d [2] 33 50 [2] 31 51 [2] 2a 57 [2] 36 50 [2] 2a 7f }

  condition:
    any of them
}