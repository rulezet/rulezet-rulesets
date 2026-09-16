rule TTP_XOR_QUAD_CurrentVersionRun_7054 {
  strings:
    $key_7054 = { 23 3b [2] 07 35 [2] 2c 19 [2] 02 3b [2] 16 20 [2] 19 3a [2] 07 27 [2] 05 26 [2] 1e 20 [2] 02 27 [2] 1e 08 }

  condition:
    any of them
}