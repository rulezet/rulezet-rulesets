rule TTP_XOR_QUAD_CurrentVersionRun_67f3 {
  strings:
    $key_67f3 = { 34 9c [2] 10 92 [2] 3b be [2] 15 9c [2] 01 87 [2] 0e 9d [2] 10 80 [2] 12 81 [2] 09 87 [2] 15 80 [2] 09 af }

  condition:
    any of them
}