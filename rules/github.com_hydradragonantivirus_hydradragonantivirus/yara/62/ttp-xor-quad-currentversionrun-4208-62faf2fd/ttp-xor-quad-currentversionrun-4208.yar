rule TTP_XOR_QUAD_CurrentVersionRun_4208 {
  strings:
    $key_4208 = { 11 67 [2] 35 69 [2] 1e 45 [2] 30 67 [2] 24 7c [2] 2b 66 [2] 35 7b [2] 37 7a [2] 2c 7c [2] 30 7b [2] 2c 54 }

  condition:
    any of them
}