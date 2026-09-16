rule TTP_XOR_QUAD_CurrentVersionRun_68f3 {
  strings:
    $key_68f3 = { 3b 9c [2] 1f 92 [2] 34 be [2] 1a 9c [2] 0e 87 [2] 01 9d [2] 1f 80 [2] 1d 81 [2] 06 87 [2] 1a 80 [2] 06 af }

  condition:
    any of them
}