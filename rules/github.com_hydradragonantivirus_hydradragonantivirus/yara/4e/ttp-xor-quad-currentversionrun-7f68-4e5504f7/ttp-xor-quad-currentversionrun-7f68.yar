rule TTP_XOR_QUAD_CurrentVersionRun_7f68 {
  strings:
    $key_7f68 = { 2c 07 [2] 08 09 [2] 23 25 [2] 0d 07 [2] 19 1c [2] 16 06 [2] 08 1b [2] 0a 1a [2] 11 1c [2] 0d 1b [2] 11 34 }

  condition:
    any of them
}