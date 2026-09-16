rule TTP_XOR_QUAD_CurrentVersionRun_7068 {
  strings:
    $key_7068 = { 23 07 [2] 07 09 [2] 2c 25 [2] 02 07 [2] 16 1c [2] 19 06 [2] 07 1b [2] 05 1a [2] 1e 1c [2] 02 1b [2] 1e 34 }

  condition:
    any of them
}