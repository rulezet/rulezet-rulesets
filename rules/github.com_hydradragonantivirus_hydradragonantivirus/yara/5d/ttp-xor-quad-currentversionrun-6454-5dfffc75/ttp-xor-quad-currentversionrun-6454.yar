rule TTP_XOR_QUAD_CurrentVersionRun_6454 {
  strings:
    $key_6454 = { 37 3b [2] 13 35 [2] 38 19 [2] 16 3b [2] 02 20 [2] 0d 3a [2] 13 27 [2] 11 26 [2] 0a 20 [2] 16 27 [2] 0a 08 }

  condition:
    any of them
}