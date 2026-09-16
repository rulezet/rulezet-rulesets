rule TTP_XOR_QUAD_CurrentVersionRun_3e69 {
  strings:
    $key_3e69 = { 6d 06 [2] 49 08 [2] 62 24 [2] 4c 06 [2] 58 1d [2] 57 07 [2] 49 1a [2] 4b 1b [2] 50 1d [2] 4c 1a [2] 50 35 }

  condition:
    any of them
}