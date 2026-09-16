rule TTP_XOR_QUAD_CurrentVersionRun_3658 {
  strings:
    $key_3658 = { 65 37 [2] 41 39 [2] 6a 15 [2] 44 37 [2] 50 2c [2] 5f 36 [2] 41 2b [2] 43 2a [2] 58 2c [2] 44 2b [2] 58 04 }

  condition:
    any of them
}