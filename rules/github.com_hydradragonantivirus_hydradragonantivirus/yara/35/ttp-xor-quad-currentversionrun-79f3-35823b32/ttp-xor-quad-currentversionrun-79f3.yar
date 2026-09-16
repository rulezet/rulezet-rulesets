rule TTP_XOR_QUAD_CurrentVersionRun_79f3 {
  strings:
    $key_79f3 = { 2a 9c [2] 0e 92 [2] 25 be [2] 0b 9c [2] 1f 87 [2] 10 9d [2] 0e 80 [2] 0c 81 [2] 17 87 [2] 0b 80 [2] 17 af }

  condition:
    any of them
}