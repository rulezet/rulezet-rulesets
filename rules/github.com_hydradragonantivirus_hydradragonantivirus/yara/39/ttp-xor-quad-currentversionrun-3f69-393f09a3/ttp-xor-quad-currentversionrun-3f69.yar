rule TTP_XOR_QUAD_CurrentVersionRun_3f69 {
  strings:
    $key_3f69 = { 6c 06 [2] 48 08 [2] 63 24 [2] 4d 06 [2] 59 1d [2] 56 07 [2] 48 1a [2] 4a 1b [2] 51 1d [2] 4d 1a [2] 51 35 }

  condition:
    any of them
}