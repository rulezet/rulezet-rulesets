rule TTP_XOR_QUAD_CurrentVersionRun_5af3 {
  strings:
    $key_5af3 = { 09 9c [2] 2d 92 [2] 06 be [2] 28 9c [2] 3c 87 [2] 33 9d [2] 2d 80 [2] 2f 81 [2] 34 87 [2] 28 80 [2] 34 af }

  condition:
    any of them
}