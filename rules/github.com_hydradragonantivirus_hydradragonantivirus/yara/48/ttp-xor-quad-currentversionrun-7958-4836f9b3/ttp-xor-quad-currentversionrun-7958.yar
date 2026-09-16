rule TTP_XOR_QUAD_CurrentVersionRun_7958 {
  strings:
    $key_7958 = { 2a 37 [2] 0e 39 [2] 25 15 [2] 0b 37 [2] 1f 2c [2] 10 36 [2] 0e 2b [2] 0c 2a [2] 17 2c [2] 0b 2b [2] 17 04 }

  condition:
    any of them
}