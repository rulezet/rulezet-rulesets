rule TTP_XOR_QUAD_CurrentVersionRun_6f68 {
  strings:
    $key_6f68 = { 3c 07 [2] 18 09 [2] 33 25 [2] 1d 07 [2] 09 1c [2] 06 06 [2] 18 1b [2] 1a 1a [2] 01 1c [2] 1d 1b [2] 01 34 }

  condition:
    any of them
}