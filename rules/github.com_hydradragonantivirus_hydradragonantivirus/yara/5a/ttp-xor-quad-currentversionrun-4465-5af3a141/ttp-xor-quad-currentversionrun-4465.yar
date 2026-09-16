rule TTP_XOR_QUAD_CurrentVersionRun_4465 {
  strings:
    $key_4465 = { 17 0a [2] 33 04 [2] 18 28 [2] 36 0a [2] 22 11 [2] 2d 0b [2] 33 16 [2] 31 17 [2] 2a 11 [2] 36 16 [2] 2a 39 }

  condition:
    any of them
}