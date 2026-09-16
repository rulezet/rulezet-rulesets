rule TTP_XOR_QUAD_CurrentVersionRun_5557 {
  strings:
    $key_5557 = { 06 38 [2] 22 36 [2] 09 1a [2] 27 38 [2] 33 23 [2] 3c 39 [2] 22 24 [2] 20 25 [2] 3b 23 [2] 27 24 [2] 3b 0b }

  condition:
    any of them
}