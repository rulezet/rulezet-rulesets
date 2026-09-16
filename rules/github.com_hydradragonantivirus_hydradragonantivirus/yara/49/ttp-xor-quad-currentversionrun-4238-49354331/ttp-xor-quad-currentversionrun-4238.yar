rule TTP_XOR_QUAD_CurrentVersionRun_4238 {
  strings:
    $key_4238 = { 11 57 [2] 35 59 [2] 1e 75 [2] 30 57 [2] 24 4c [2] 2b 56 [2] 35 4b [2] 37 4a [2] 2c 4c [2] 30 4b [2] 2c 64 }

  condition:
    any of them
}