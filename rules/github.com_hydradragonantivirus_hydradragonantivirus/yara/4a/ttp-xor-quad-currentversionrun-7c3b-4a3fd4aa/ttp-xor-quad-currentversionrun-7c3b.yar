rule TTP_XOR_QUAD_CurrentVersionRun_7c3b {
  strings:
    $key_7c3b = { 2f 54 [2] 0b 5a [2] 20 76 [2] 0e 54 [2] 1a 4f [2] 15 55 [2] 0b 48 [2] 09 49 [2] 12 4f [2] 0e 48 [2] 12 67 }

  condition:
    any of them
}