rule TTP_XOR_QUAD_CurrentVersionRun_15f3 {
  strings:
    $key_15f3 = { 46 9c [2] 62 92 [2] 49 be [2] 67 9c [2] 73 87 [2] 7c 9d [2] 62 80 [2] 60 81 [2] 7b 87 [2] 67 80 [2] 7b af }

  condition:
    any of them
}