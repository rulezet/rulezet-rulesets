rule TTP_XOR_QUAD_CurrentVersionRun_2a77 {
  strings:
    $key_2a77 = { 79 18 [2] 5d 16 [2] 76 3a [2] 58 18 [2] 4c 03 [2] 43 19 [2] 5d 04 [2] 5f 05 [2] 44 03 [2] 58 04 [2] 44 2b }

  condition:
    any of them
}