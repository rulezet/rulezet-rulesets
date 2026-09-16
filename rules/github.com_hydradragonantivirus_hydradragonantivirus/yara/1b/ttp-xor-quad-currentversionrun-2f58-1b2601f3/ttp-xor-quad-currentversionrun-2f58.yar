rule TTP_XOR_QUAD_CurrentVersionRun_2f58 {
  strings:
    $key_2f58 = { 7c 37 [2] 58 39 [2] 73 15 [2] 5d 37 [2] 49 2c [2] 46 36 [2] 58 2b [2] 5a 2a [2] 41 2c [2] 5d 2b [2] 41 04 }

  condition:
    any of them
}