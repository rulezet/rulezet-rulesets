rule TTP_XOR_QUAD_CurrentVersionRun_7c64 {
  strings:
    $key_7c64 = { 2f 0b [2] 0b 05 [2] 20 29 [2] 0e 0b [2] 1a 10 [2] 15 0a [2] 0b 17 [2] 09 16 [2] 12 10 [2] 0e 17 [2] 12 38 }

  condition:
    any of them
}