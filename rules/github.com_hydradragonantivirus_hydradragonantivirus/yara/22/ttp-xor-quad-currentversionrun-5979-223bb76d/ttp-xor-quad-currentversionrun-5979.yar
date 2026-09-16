rule TTP_XOR_QUAD_CurrentVersionRun_5979 {
  strings:
    $key_5979 = { 0a 16 [2] 2e 18 [2] 05 34 [2] 2b 16 [2] 3f 0d [2] 30 17 [2] 2e 0a [2] 2c 0b [2] 37 0d [2] 2b 0a [2] 37 25 }

  condition:
    any of them
}