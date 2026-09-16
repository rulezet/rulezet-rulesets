rule TTP_XOR_QUAD_CurrentVersionRun_3f77 {
  strings:
    $key_3f77 = { 6c 18 [2] 48 16 [2] 63 3a [2] 4d 18 [2] 59 03 [2] 56 19 [2] 48 04 [2] 4a 05 [2] 51 03 [2] 4d 04 [2] 51 2b }

  condition:
    any of them
}