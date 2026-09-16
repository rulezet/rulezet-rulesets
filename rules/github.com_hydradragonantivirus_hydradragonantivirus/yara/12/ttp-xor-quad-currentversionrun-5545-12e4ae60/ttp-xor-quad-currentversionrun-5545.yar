rule TTP_XOR_QUAD_CurrentVersionRun_5545 {
  strings:
    $key_5545 = { 06 2a [2] 22 24 [2] 09 08 [2] 27 2a [2] 33 31 [2] 3c 2b [2] 22 36 [2] 20 37 [2] 3b 31 [2] 27 36 [2] 3b 19 }

  condition:
    any of them
}