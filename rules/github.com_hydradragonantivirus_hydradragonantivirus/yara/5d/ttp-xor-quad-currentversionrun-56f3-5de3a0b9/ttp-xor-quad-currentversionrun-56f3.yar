rule TTP_XOR_QUAD_CurrentVersionRun_56f3 {
  strings:
    $key_56f3 = { 05 9c [2] 21 92 [2] 0a be [2] 24 9c [2] 30 87 [2] 3f 9d [2] 21 80 [2] 23 81 [2] 38 87 [2] 24 80 [2] 38 af }

  condition:
    any of them
}