rule TTP_XOR_QUAD_CurrentVersionRun_7c4b {
  strings:
    $key_7c4b = { 2f 24 [2] 0b 2a [2] 20 06 [2] 0e 24 [2] 1a 3f [2] 15 25 [2] 0b 38 [2] 09 39 [2] 12 3f [2] 0e 38 [2] 12 17 }

  condition:
    any of them
}