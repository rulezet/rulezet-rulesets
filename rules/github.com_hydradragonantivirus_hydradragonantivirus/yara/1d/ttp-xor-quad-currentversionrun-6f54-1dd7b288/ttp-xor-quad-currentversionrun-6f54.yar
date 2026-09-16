rule TTP_XOR_QUAD_CurrentVersionRun_6f54 {
  strings:
    $key_6f54 = { 3c 3b [2] 18 35 [2] 33 19 [2] 1d 3b [2] 09 20 [2] 06 3a [2] 18 27 [2] 1a 26 [2] 01 20 [2] 1d 27 [2] 01 08 }

  condition:
    any of them
}