rule TTP_XOR_QUAD_CurrentVersionRun_5df3 {
  strings:
    $key_5df3 = { 0e 9c [2] 2a 92 [2] 01 be [2] 2f 9c [2] 3b 87 [2] 34 9d [2] 2a 80 [2] 28 81 [2] 33 87 [2] 2f 80 [2] 33 af }

  condition:
    any of them
}