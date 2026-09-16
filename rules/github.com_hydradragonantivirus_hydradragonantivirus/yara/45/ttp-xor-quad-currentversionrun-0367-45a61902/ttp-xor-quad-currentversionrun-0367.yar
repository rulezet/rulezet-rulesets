rule TTP_XOR_QUAD_CurrentVersionRun_0367 {
  strings:
    $key_0367 = { 50 08 [2] 74 06 [2] 5f 2a [2] 71 08 [2] 65 13 [2] 6a 09 [2] 74 14 [2] 76 15 [2] 6d 13 [2] 71 14 [2] 6d 3b }

  condition:
    any of them
}