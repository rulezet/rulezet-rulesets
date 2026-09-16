rule TTP_XOR_QUAD_CurrentVersionRun_28f3 {
  strings:
    $key_28f3 = { 7b 9c [2] 5f 92 [2] 74 be [2] 5a 9c [2] 4e 87 [2] 41 9d [2] 5f 80 [2] 5d 81 [2] 46 87 [2] 5a 80 [2] 46 af }

  condition:
    any of them
}