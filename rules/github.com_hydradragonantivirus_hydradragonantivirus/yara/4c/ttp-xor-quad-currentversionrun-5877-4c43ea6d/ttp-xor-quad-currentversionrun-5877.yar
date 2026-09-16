rule TTP_XOR_QUAD_CurrentVersionRun_5877 {
  strings:
    $key_5877 = { 0b 18 [2] 2f 16 [2] 04 3a [2] 2a 18 [2] 3e 03 [2] 31 19 [2] 2f 04 [2] 2d 05 [2] 36 03 [2] 2a 04 [2] 36 2b }

  condition:
    any of them
}