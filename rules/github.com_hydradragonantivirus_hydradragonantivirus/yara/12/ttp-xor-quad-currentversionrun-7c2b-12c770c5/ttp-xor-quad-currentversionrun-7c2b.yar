rule TTP_XOR_QUAD_CurrentVersionRun_7c2b {
  strings:
    $key_7c2b = { 2f 44 [2] 0b 4a [2] 20 66 [2] 0e 44 [2] 1a 5f [2] 15 45 [2] 0b 58 [2] 09 59 [2] 12 5f [2] 0e 58 [2] 12 77 }

  condition:
    any of them
}