rule TTP_XOR_QUAD_CurrentVersionRun_e375 {
  strings:
    $key_e375 = { b0 1a [2] 94 14 [2] bf 38 [2] 91 1a [2] 85 01 [2] 8a 1b [2] 94 06 [2] 96 07 [2] 8d 01 [2] 91 06 [2] 8d 29 }

  condition:
    any of them
}