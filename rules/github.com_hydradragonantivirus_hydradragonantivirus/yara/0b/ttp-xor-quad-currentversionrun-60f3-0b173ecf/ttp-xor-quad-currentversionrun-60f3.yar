rule TTP_XOR_QUAD_CurrentVersionRun_60f3 {
  strings:
    $key_60f3 = { 33 9c [2] 17 92 [2] 3c be [2] 12 9c [2] 06 87 [2] 09 9d [2] 17 80 [2] 15 81 [2] 0e 87 [2] 12 80 [2] 0e af }

  condition:
    any of them
}