rule TTP_XOR_QUAD_CurrentVersionRun_4165 {
  strings:
    $key_4165 = { 12 0a [2] 36 04 [2] 1d 28 [2] 33 0a [2] 27 11 [2] 28 0b [2] 36 16 [2] 34 17 [2] 2f 11 [2] 33 16 [2] 2f 39 }

  condition:
    any of them
}