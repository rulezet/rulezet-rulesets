rule TTP_XOR_QUAD_CurrentVersionRun_6568 {
  strings:
    $key_6568 = { 36 07 [2] 12 09 [2] 39 25 [2] 17 07 [2] 03 1c [2] 0c 06 [2] 12 1b [2] 10 1a [2] 0b 1c [2] 17 1b [2] 0b 34 }

  condition:
    any of them
}