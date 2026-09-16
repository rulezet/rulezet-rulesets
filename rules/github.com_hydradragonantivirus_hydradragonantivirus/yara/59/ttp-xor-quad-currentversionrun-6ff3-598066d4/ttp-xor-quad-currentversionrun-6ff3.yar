rule TTP_XOR_QUAD_CurrentVersionRun_6ff3 {
  strings:
    $key_6ff3 = { 3c 9c [2] 18 92 [2] 33 be [2] 1d 9c [2] 09 87 [2] 06 9d [2] 18 80 [2] 1a 81 [2] 01 87 [2] 1d 80 [2] 01 af }

  condition:
    any of them
}