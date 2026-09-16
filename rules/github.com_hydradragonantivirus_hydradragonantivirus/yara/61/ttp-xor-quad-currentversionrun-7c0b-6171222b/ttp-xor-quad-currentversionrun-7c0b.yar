rule TTP_XOR_QUAD_CurrentVersionRun_7c0b {
  strings:
    $key_7c0b = { 2f 64 [2] 0b 6a [2] 20 46 [2] 0e 64 [2] 1a 7f [2] 15 65 [2] 0b 78 [2] 09 79 [2] 12 7f [2] 0e 78 [2] 12 57 }

  condition:
    any of them
}