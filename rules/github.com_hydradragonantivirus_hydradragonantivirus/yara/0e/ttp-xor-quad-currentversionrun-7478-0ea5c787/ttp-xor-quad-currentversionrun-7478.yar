rule TTP_XOR_QUAD_CurrentVersionRun_7478 {
  strings:
    $key_7478 = { 27 17 [2] 03 19 [2] 28 35 [2] 06 17 [2] 12 0c [2] 1d 16 [2] 03 0b [2] 01 0a [2] 1a 0c [2] 06 0b [2] 1a 24 }

  condition:
    any of them
}