rule TTP_XOR_QUAD_CurrentVersionRun_42e5 {
  strings:
    $key_42e5 = { 11 8a [2] 35 84 [2] 1e a8 [2] 30 8a [2] 24 91 [2] 2b 8b [2] 35 96 [2] 37 97 [2] 2c 91 [2] 30 96 [2] 2c b9 }

  condition:
    any of them
}