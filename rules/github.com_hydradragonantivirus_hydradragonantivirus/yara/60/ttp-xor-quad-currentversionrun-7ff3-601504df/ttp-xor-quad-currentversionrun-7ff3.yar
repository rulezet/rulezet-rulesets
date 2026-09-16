rule TTP_XOR_QUAD_CurrentVersionRun_7ff3 {
  strings:
    $key_7ff3 = { 2c 9c [2] 08 92 [2] 23 be [2] 0d 9c [2] 19 87 [2] 16 9d [2] 08 80 [2] 0a 81 [2] 11 87 [2] 0d 80 [2] 11 af }

  condition:
    any of them
}