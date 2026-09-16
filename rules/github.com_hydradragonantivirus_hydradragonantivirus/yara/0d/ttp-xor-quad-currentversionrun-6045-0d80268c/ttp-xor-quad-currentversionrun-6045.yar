rule TTP_XOR_QUAD_CurrentVersionRun_6045 {
  strings:
    $key_6045 = { 33 2a [2] 17 24 [2] 3c 08 [2] 12 2a [2] 06 31 [2] 09 2b [2] 17 36 [2] 15 37 [2] 0e 31 [2] 12 36 [2] 0e 19 }

  condition:
    any of them
}