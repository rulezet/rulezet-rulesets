rule TTP_XOR_QUAD_CurrentVersionRun_2158 {
  strings:
    $key_2158 = { 72 37 [2] 56 39 [2] 7d 15 [2] 53 37 [2] 47 2c [2] 48 36 [2] 56 2b [2] 54 2a [2] 4f 2c [2] 53 2b [2] 4f 04 }

  condition:
    any of them
}