rule TTP_XOR_QUAD_CurrentVersionRun_3c75 {
  strings:
    $key_3c75 = { 6f 1a [2] 4b 14 [2] 60 38 [2] 4e 1a [2] 5a 01 [2] 55 1b [2] 4b 06 [2] 49 07 [2] 52 01 [2] 4e 06 [2] 52 29 }

  condition:
    any of them
}