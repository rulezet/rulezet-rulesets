rule TTP_XOR_QUAD_CurrentVersionRun_6258 {
  strings:
    $key_6258 = { 31 37 [2] 15 39 [2] 3e 15 [2] 10 37 [2] 04 2c [2] 0b 36 [2] 15 2b [2] 17 2a [2] 0c 2c [2] 10 2b [2] 0c 04 }

  condition:
    any of them
}