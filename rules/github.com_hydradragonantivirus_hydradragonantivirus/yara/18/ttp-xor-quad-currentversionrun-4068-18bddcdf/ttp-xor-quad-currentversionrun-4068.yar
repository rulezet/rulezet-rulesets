rule TTP_XOR_QUAD_CurrentVersionRun_4068 {
  strings:
    $key_4068 = { 13 07 [2] 37 09 [2] 1c 25 [2] 32 07 [2] 26 1c [2] 29 06 [2] 37 1b [2] 35 1a [2] 2e 1c [2] 32 1b [2] 2e 34 }

  condition:
    any of them
}