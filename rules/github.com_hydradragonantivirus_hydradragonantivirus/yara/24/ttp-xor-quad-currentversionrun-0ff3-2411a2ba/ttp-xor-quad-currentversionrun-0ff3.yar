rule TTP_XOR_QUAD_CurrentVersionRun_0ff3 {
  strings:
    $key_0ff3 = { 5c 9c [2] 78 92 [2] 53 be [2] 7d 9c [2] 69 87 [2] 66 9d [2] 78 80 [2] 7a 81 [2] 61 87 [2] 7d 80 [2] 61 af }

  condition:
    any of them
}