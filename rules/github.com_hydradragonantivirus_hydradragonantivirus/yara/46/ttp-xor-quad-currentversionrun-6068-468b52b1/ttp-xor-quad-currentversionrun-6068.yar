rule TTP_XOR_QUAD_CurrentVersionRun_6068 {
  strings:
    $key_6068 = { 33 07 [2] 17 09 [2] 3c 25 [2] 12 07 [2] 06 1c [2] 09 06 [2] 17 1b [2] 15 1a [2] 0e 1c [2] 12 1b [2] 0e 34 }

  condition:
    any of them
}