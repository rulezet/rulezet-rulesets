rule TTP_XOR_QUAD_CurrentVersionRun_6d69 {
  strings:
    $key_6d69 = { 3e 06 [2] 1a 08 [2] 31 24 [2] 1f 06 [2] 0b 1d [2] 04 07 [2] 1a 1a [2] 18 1b [2] 03 1d [2] 1f 1a [2] 03 35 }

  condition:
    any of them
}