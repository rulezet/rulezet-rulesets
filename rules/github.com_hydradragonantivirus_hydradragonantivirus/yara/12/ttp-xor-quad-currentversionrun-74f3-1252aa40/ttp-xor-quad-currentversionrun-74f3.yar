rule TTP_XOR_QUAD_CurrentVersionRun_74f3 {
  strings:
    $key_74f3 = { 27 9c [2] 03 92 [2] 28 be [2] 06 9c [2] 12 87 [2] 1d 9d [2] 03 80 [2] 01 81 [2] 1a 87 [2] 06 80 [2] 1a af }

  condition:
    any of them
}