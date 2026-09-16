rule TTP_XOR_QUAD_CurrentVersionRun_2658 {
  strings:
    $key_2658 = { 75 37 [2] 51 39 [2] 7a 15 [2] 54 37 [2] 40 2c [2] 4f 36 [2] 51 2b [2] 53 2a [2] 48 2c [2] 54 2b [2] 48 04 }

  condition:
    any of them
}