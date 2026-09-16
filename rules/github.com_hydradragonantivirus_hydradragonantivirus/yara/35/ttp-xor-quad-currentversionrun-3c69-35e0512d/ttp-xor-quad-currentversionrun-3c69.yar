rule TTP_XOR_QUAD_CurrentVersionRun_3c69 {
  strings:
    $key_3c69 = { 6f 06 [2] 4b 08 [2] 60 24 [2] 4e 06 [2] 5a 1d [2] 55 07 [2] 4b 1a [2] 49 1b [2] 52 1d [2] 4e 1a [2] 52 35 }

  condition:
    any of them
}