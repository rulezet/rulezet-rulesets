rule TTP_XOR_QUAD_CurrentVersionRun_7af3 {
  strings:
    $key_7af3 = { 29 9c [2] 0d 92 [2] 26 be [2] 08 9c [2] 1c 87 [2] 13 9d [2] 0d 80 [2] 0f 81 [2] 14 87 [2] 08 80 [2] 14 af }

  condition:
    any of them
}