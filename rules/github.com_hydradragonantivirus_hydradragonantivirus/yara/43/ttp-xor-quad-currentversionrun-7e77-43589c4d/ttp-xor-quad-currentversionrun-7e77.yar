rule TTP_XOR_QUAD_CurrentVersionRun_7e77 {
  strings:
    $key_7e77 = { 2d 18 [2] 09 16 [2] 22 3a [2] 0c 18 [2] 18 03 [2] 17 19 [2] 09 04 [2] 0b 05 [2] 10 03 [2] 0c 04 [2] 10 2b }

  condition:
    any of them
}