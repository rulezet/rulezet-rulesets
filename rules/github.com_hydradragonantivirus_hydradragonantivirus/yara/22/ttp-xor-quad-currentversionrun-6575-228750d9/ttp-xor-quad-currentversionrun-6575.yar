rule TTP_XOR_QUAD_CurrentVersionRun_6575 {
  strings:
    $key_6575 = { 36 1a [2] 12 14 [2] 39 38 [2] 17 1a [2] 03 01 [2] 0c 1b [2] 12 06 [2] 10 07 [2] 0b 01 [2] 17 06 [2] 0b 29 }

  condition:
    any of them
}