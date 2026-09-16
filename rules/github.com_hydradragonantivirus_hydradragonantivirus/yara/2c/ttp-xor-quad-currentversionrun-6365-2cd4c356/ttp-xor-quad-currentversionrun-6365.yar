rule TTP_XOR_QUAD_CurrentVersionRun_6365 {
  strings:
    $key_6365 = { 30 0a [2] 14 04 [2] 3f 28 [2] 11 0a [2] 05 11 [2] 0a 0b [2] 14 16 [2] 16 17 [2] 0d 11 [2] 11 16 [2] 0d 39 }

  condition:
    any of them
}