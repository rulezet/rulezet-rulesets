rule TTP_XOR_QUAD_CurrentVersionRun_42e8 {
  strings:
    $key_42e8 = { 11 87 [2] 35 89 [2] 1e a5 [2] 30 87 [2] 24 9c [2] 2b 86 [2] 35 9b [2] 37 9a [2] 2c 9c [2] 30 9b [2] 2c b4 }

  condition:
    any of them
}