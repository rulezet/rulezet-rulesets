rule TTP_XOR_QUAD_CurrentVersionRun_6077 {
  strings:
    $key_6077 = { 33 18 [2] 17 16 [2] 3c 3a [2] 12 18 [2] 06 03 [2] 09 19 [2] 17 04 [2] 15 05 [2] 0e 03 [2] 12 04 [2] 0e 2b }

  condition:
    any of them
}