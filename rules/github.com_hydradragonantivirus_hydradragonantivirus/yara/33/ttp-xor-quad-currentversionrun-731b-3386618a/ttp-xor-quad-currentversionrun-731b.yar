rule TTP_XOR_QUAD_CurrentVersionRun_731b {
  strings:
    $key_731b = { 20 74 [2] 04 7a [2] 2f 56 [2] 01 74 [2] 15 6f [2] 1a 75 [2] 04 68 [2] 06 69 [2] 1d 6f [2] 01 68 [2] 1d 47 }

  condition:
    any of them
}