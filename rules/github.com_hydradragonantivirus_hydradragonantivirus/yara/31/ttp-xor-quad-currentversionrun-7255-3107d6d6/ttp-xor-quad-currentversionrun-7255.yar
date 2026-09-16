rule TTP_XOR_QUAD_CurrentVersionRun_7255 {
  strings:
    $key_7255 = { 21 3a [2] 05 34 [2] 2e 18 [2] 00 3a [2] 14 21 [2] 1b 3b [2] 05 26 [2] 07 27 [2] 1c 21 [2] 00 26 [2] 1c 09 }

  condition:
    any of them
}