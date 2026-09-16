rule TTP_XOR_QUAD_CurrentVersionRun_7a77 {
  strings:
    $key_7a77 = { 29 18 [2] 0d 16 [2] 26 3a [2] 08 18 [2] 1c 03 [2] 13 19 [2] 0d 04 [2] 0f 05 [2] 14 03 [2] 08 04 [2] 14 2b }

  condition:
    any of them
}