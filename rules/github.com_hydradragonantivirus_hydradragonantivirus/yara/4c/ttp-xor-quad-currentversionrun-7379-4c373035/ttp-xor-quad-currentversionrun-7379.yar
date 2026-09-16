rule TTP_XOR_QUAD_CurrentVersionRun_7379 {
  strings:
    $key_7379 = { 20 16 [2] 04 18 [2] 2f 34 [2] 01 16 [2] 15 0d [2] 1a 17 [2] 04 0a [2] 06 0b [2] 1d 0d [2] 01 0a [2] 1d 25 }

  condition:
    any of them
}