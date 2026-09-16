rule TTP_XOR_QUAD_CurrentVersionRun_7367 {
  strings:
    $key_7367 = { 20 08 [2] 04 06 [2] 2f 2a [2] 01 08 [2] 15 13 [2] 1a 09 [2] 04 14 [2] 06 15 [2] 1d 13 [2] 01 14 [2] 1d 3b }

  condition:
    any of them
}