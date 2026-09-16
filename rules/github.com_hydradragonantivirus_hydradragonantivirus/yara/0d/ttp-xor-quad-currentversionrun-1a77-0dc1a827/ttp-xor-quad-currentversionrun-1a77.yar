rule TTP_XOR_QUAD_CurrentVersionRun_1a77 {
  strings:
    $key_1a77 = { 49 18 [2] 6d 16 [2] 46 3a [2] 68 18 [2] 7c 03 [2] 73 19 [2] 6d 04 [2] 6f 05 [2] 74 03 [2] 68 04 [2] 74 2b }

  condition:
    any of them
}