rule TTP_XOR_QUAD_CurrentVersionRun_7e57 {
  strings:
    $key_7e57 = { 2d 38 [2] 09 36 [2] 22 1a [2] 0c 38 [2] 18 23 [2] 17 39 [2] 09 24 [2] 0b 25 [2] 10 23 [2] 0c 24 [2] 10 0b }

  condition:
    any of them
}