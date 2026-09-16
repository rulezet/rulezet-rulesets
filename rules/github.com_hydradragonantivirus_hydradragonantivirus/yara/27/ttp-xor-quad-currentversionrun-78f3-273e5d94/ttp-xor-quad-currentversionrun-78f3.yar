rule TTP_XOR_QUAD_CurrentVersionRun_78f3 {
  strings:
    $key_78f3 = { 2b 9c [2] 0f 92 [2] 24 be [2] 0a 9c [2] 1e 87 [2] 11 9d [2] 0f 80 [2] 0d 81 [2] 16 87 [2] 0a 80 [2] 16 af }

  condition:
    any of them
}