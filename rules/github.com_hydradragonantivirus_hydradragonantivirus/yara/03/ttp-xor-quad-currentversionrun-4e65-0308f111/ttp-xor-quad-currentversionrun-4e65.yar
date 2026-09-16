rule TTP_XOR_QUAD_CurrentVersionRun_4e65 {
  strings:
    $key_4e65 = { 1d 0a [2] 39 04 [2] 12 28 [2] 3c 0a [2] 28 11 [2] 27 0b [2] 39 16 [2] 3b 17 [2] 20 11 [2] 3c 16 [2] 20 39 }

  condition:
    any of them
}