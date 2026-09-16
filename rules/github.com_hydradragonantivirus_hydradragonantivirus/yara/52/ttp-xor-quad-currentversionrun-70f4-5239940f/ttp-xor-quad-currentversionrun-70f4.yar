rule TTP_XOR_QUAD_CurrentVersionRun_70f4 {
  strings:
    $key_70f4 = { 23 9b [2] 07 95 [2] 2c b9 [2] 02 9b [2] 16 80 [2] 19 9a [2] 07 87 [2] 05 86 [2] 1e 80 [2] 02 87 [2] 1e a8 }

  condition:
    any of them
}