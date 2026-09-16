rule TTP_XOR_QUAD_CurrentVersionRun_7c6b {
  strings:
    $key_7c6b = { 2f 04 [2] 0b 0a [2] 20 26 [2] 0e 04 [2] 1a 1f [2] 15 05 [2] 0b 18 [2] 09 19 [2] 12 1f [2] 0e 18 [2] 12 37 }

  condition:
    any of them
}