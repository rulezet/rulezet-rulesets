rule TTP_XOR_QUAD_CurrentVersionRun_4303 {
  strings:
    $key_4303 = { 10 6c [2] 34 62 [2] 1f 4e [2] 31 6c [2] 25 77 [2] 2a 6d [2] 34 70 [2] 36 71 [2] 2d 77 [2] 31 70 [2] 2d 5f }

  condition:
    any of them
}