rule TTP_XOR_QUAD_CurrentVersionRun_70f3 {
  strings:
    $key_70f3 = { 23 9c [2] 07 92 [2] 2c be [2] 02 9c [2] 16 87 [2] 19 9d [2] 07 80 [2] 05 81 [2] 1e 87 [2] 02 80 [2] 1e af }

  condition:
    any of them
}