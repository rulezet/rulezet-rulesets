rule TTP_XOR_QUAD_CurrentVersionRun_0377 {
  strings:
    $key_0377 = { 50 18 [2] 74 16 [2] 5f 3a [2] 71 18 [2] 65 03 [2] 6a 19 [2] 74 04 [2] 76 05 [2] 6d 03 [2] 71 04 [2] 6d 2b }

  condition:
    any of them
}