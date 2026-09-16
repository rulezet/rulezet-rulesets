rule TTP_XOR_QUAD_CurrentVersionRun_607b {
  strings:
    $key_607b = { 33 14 [2] 17 1a [2] 3c 36 [2] 12 14 [2] 06 0f [2] 09 15 [2] 17 08 [2] 15 09 [2] 0e 0f [2] 12 08 [2] 0e 27 }

  condition:
    any of them
}