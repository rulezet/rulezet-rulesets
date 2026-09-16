rule TTP_XOR_QUAD_CurrentVersionRun_6464 {
  strings:
    $key_6464 = { 37 0b [2] 13 05 [2] 38 29 [2] 16 0b [2] 02 10 [2] 0d 0a [2] 13 17 [2] 11 16 [2] 0a 10 [2] 16 17 [2] 0a 38 }

  condition:
    any of them
}