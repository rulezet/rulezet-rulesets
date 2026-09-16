rule TTP_XOR_QUAD_CurrentVersionRun_7175 {
  strings:
    $key_7175 = { 22 1a [2] 06 14 [2] 2d 38 [2] 03 1a [2] 17 01 [2] 18 1b [2] 06 06 [2] 04 07 [2] 1f 01 [2] 03 06 [2] 1f 29 }

  condition:
    any of them
}