rule TTP_XOR_QUAD_CurrentVersionRun_6465 {
  strings:
    $key_6465 = { 37 0a [2] 13 04 [2] 38 28 [2] 16 0a [2] 02 11 [2] 0d 0b [2] 13 16 [2] 11 17 [2] 0a 11 [2] 16 16 [2] 0a 39 }

  condition:
    any of them
}