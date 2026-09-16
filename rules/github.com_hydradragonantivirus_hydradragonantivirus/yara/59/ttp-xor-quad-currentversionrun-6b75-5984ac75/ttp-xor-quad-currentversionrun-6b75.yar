rule TTP_XOR_QUAD_CurrentVersionRun_6b75 {
  strings:
    $key_6b75 = { 38 1a [2] 1c 14 [2] 37 38 [2] 19 1a [2] 0d 01 [2] 02 1b [2] 1c 06 [2] 1e 07 [2] 05 01 [2] 19 06 [2] 05 29 }

  condition:
    any of them
}