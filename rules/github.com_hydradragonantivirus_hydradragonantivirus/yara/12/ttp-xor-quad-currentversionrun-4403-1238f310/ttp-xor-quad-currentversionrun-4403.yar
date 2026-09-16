rule TTP_XOR_QUAD_CurrentVersionRun_4403 {
  strings:
    $key_4403 = { 17 6c [2] 33 62 [2] 18 4e [2] 36 6c [2] 22 77 [2] 2d 6d [2] 33 70 [2] 31 71 [2] 2a 77 [2] 36 70 [2] 2a 5f }

  condition:
    any of them
}