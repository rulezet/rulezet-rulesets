rule TTP_XOR_QUAD_CurrentVersionRun_5869 {
  strings:
    $key_5869 = { 0b 06 [2] 2f 08 [2] 04 24 [2] 2a 06 [2] 3e 1d [2] 31 07 [2] 2f 1a [2] 2d 1b [2] 36 1d [2] 2a 1a [2] 36 35 }

  condition:
    any of them
}