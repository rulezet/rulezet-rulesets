rule TTP_XOR_QUAD_CurrentVersionRun_2377 {
  strings:
    $key_2377 = { 70 18 [2] 54 16 [2] 7f 3a [2] 51 18 [2] 45 03 [2] 4a 19 [2] 54 04 [2] 56 05 [2] 4d 03 [2] 51 04 [2] 4d 2b }

  condition:
    any of them
}