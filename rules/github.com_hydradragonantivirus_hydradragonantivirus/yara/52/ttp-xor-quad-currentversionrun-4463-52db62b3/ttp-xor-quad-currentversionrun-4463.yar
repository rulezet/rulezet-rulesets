rule TTP_XOR_QUAD_CurrentVersionRun_4463 {
  strings:
    $key_4463 = { 17 0c [2] 33 02 [2] 18 2e [2] 36 0c [2] 22 17 [2] 2d 0d [2] 33 10 [2] 31 11 [2] 2a 17 [2] 36 10 [2] 2a 3f }

  condition:
    any of them
}