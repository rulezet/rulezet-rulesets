rule TTP_XOR_QUAD_CurrentVersionRun_7555 {
  strings:
    $key_7555 = { 26 3a [2] 02 34 [2] 29 18 [2] 07 3a [2] 13 21 [2] 1c 3b [2] 02 26 [2] 00 27 [2] 1b 21 [2] 07 26 [2] 1b 09 }

  condition:
    any of them
}