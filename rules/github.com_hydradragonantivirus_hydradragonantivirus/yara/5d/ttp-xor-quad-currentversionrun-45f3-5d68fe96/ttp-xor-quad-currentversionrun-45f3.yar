rule TTP_XOR_QUAD_CurrentVersionRun_45f3 {
  strings:
    $key_45f3 = { 16 9c [2] 32 92 [2] 19 be [2] 37 9c [2] 23 87 [2] 2c 9d [2] 32 80 [2] 30 81 [2] 2b 87 [2] 37 80 [2] 2b af }

  condition:
    any of them
}