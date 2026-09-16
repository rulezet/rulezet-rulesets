rule TTP_XOR_QUAD_CurrentVersionRun_2358 {
  strings:
    $key_2358 = { 70 37 [2] 54 39 [2] 7f 15 [2] 51 37 [2] 45 2c [2] 4a 36 [2] 54 2b [2] 56 2a [2] 4d 2c [2] 51 2b [2] 4d 04 }

  condition:
    any of them
}