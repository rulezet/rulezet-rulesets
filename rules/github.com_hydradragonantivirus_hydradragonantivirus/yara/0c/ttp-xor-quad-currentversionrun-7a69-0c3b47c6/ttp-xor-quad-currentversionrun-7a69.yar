rule TTP_XOR_QUAD_CurrentVersionRun_7a69 {
  strings:
    $key_7a69 = { 29 06 [2] 0d 08 [2] 26 24 [2] 08 06 [2] 1c 1d [2] 13 07 [2] 0d 1a [2] 0f 1b [2] 14 1d [2] 08 1a [2] 14 35 }

  condition:
    any of them
}