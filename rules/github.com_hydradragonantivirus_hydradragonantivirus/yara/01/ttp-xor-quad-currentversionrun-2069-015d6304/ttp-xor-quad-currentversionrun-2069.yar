rule TTP_XOR_QUAD_CurrentVersionRun_2069 {
  strings:
    $key_2069 = { 73 06 [2] 57 08 [2] 7c 24 [2] 52 06 [2] 46 1d [2] 49 07 [2] 57 1a [2] 55 1b [2] 4e 1d [2] 52 1a [2] 4e 35 }

  condition:
    any of them
}