rule TTP_XOR_QUAD_CurrentVersionRun_7c04 {
  strings:
    $key_7c04 = { 2f 6b [2] 0b 65 [2] 20 49 [2] 0e 6b [2] 1a 70 [2] 15 6a [2] 0b 77 [2] 09 76 [2] 12 70 [2] 0e 77 [2] 12 58 }

  condition:
    any of them
}