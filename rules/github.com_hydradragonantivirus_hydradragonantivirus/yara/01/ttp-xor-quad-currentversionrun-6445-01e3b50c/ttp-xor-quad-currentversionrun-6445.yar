rule TTP_XOR_QUAD_CurrentVersionRun_6445 {
  strings:
    $key_6445 = { 37 2a [2] 13 24 [2] 38 08 [2] 16 2a [2] 02 31 [2] 0d 2b [2] 13 36 [2] 11 37 [2] 0a 31 [2] 16 36 [2] 0a 19 }

  condition:
    any of them
}