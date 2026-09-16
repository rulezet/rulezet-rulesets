rule TTP_XOR_QUAD_CurrentVersionRun_6367 {
  strings:
    $key_6367 = { 30 08 [2] 14 06 [2] 3f 2a [2] 11 08 [2] 05 13 [2] 0a 09 [2] 14 14 [2] 16 15 [2] 0d 13 [2] 11 14 [2] 0d 3b }

  condition:
    any of them
}