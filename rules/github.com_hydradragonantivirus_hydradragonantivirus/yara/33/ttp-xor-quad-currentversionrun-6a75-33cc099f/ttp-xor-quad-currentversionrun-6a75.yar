rule TTP_XOR_QUAD_CurrentVersionRun_6a75 {
  strings:
    $key_6a75 = { 39 1a [2] 1d 14 [2] 36 38 [2] 18 1a [2] 0c 01 [2] 03 1b [2] 1d 06 [2] 1f 07 [2] 04 01 [2] 18 06 [2] 04 29 }

  condition:
    any of them
}