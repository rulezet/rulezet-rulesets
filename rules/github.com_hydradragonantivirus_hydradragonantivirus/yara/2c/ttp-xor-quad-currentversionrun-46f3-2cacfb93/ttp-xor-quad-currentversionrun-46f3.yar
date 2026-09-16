rule TTP_XOR_QUAD_CurrentVersionRun_46f3 {
  strings:
    $key_46f3 = { 15 9c [2] 31 92 [2] 1a be [2] 34 9c [2] 20 87 [2] 2f 9d [2] 31 80 [2] 33 81 [2] 28 87 [2] 34 80 [2] 28 af }

  condition:
    any of them
}