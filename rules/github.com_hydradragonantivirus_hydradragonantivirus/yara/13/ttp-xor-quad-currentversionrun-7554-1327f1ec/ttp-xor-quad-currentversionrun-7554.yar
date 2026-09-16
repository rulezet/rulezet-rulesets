rule TTP_XOR_QUAD_CurrentVersionRun_7554 {
  strings:
    $key_7554 = { 26 3b [2] 02 35 [2] 29 19 [2] 07 3b [2] 13 20 [2] 1c 3a [2] 02 27 [2] 00 26 [2] 1b 20 [2] 07 27 [2] 1b 08 }

  condition:
    any of them
}