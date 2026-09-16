rule TTP_XOR_QUAD_CurrentVersionRun_6f45 {
  strings:
    $key_6f45 = { 3c 2a [2] 18 24 [2] 33 08 [2] 1d 2a [2] 09 31 [2] 06 2b [2] 18 36 [2] 1a 37 [2] 01 31 [2] 1d 36 [2] 01 19 }

  condition:
    any of them
}