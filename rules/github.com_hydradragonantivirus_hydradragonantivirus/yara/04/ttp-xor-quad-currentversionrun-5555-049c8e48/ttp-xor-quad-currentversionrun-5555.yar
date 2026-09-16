rule TTP_XOR_QUAD_CurrentVersionRun_5555 {
  strings:
    $key_5555 = { 06 3a [2] 22 34 [2] 09 18 [2] 27 3a [2] 33 21 [2] 3c 3b [2] 22 26 [2] 20 27 [2] 3b 21 [2] 27 26 [2] 3b 09 }

  condition:
    any of them
}