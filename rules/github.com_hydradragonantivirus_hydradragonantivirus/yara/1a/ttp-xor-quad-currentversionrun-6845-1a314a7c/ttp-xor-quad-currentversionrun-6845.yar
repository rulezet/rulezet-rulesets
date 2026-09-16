rule TTP_XOR_QUAD_CurrentVersionRun_6845 {
  strings:
    $key_6845 = { 3b 2a [2] 1f 24 [2] 34 08 [2] 1a 2a [2] 0e 31 [2] 01 2b [2] 1f 36 [2] 1d 37 [2] 06 31 [2] 1a 36 [2] 06 19 }

  condition:
    any of them
}