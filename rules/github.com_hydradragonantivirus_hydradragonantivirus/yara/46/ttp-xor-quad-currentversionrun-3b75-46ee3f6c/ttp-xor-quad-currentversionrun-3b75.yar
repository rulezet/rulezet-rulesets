rule TTP_XOR_QUAD_CurrentVersionRun_3b75 {
  strings:
    $key_3b75 = { 68 1a [2] 4c 14 [2] 67 38 [2] 49 1a [2] 5d 01 [2] 52 1b [2] 4c 06 [2] 4e 07 [2] 55 01 [2] 49 06 [2] 55 29 }

  condition:
    any of them
}