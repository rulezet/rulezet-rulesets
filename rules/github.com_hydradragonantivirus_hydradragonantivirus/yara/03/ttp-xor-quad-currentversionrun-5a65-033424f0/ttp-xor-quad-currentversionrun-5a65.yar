rule TTP_XOR_QUAD_CurrentVersionRun_5a65 {
  strings:
    $key_5a65 = { 09 0a [2] 2d 04 [2] 06 28 [2] 28 0a [2] 3c 11 [2] 33 0b [2] 2d 16 [2] 2f 17 [2] 34 11 [2] 28 16 [2] 34 39 }

  condition:
    any of them
}