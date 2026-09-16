rule TTP_XOR_QUAD_CurrentVersionRun_6577 {
  strings:
    $key_6577 = { 36 18 [2] 12 16 [2] 39 3a [2] 17 18 [2] 03 03 [2] 0c 19 [2] 12 04 [2] 10 05 [2] 0b 03 [2] 17 04 [2] 0b 2b }

  condition:
    any of them
}