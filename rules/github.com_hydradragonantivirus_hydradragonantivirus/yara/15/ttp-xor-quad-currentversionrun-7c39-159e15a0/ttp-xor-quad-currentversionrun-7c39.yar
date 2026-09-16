rule TTP_XOR_QUAD_CurrentVersionRun_7c39 {
  strings:
    $key_7c39 = { 2f 56 [2] 0b 58 [2] 20 74 [2] 0e 56 [2] 1a 4d [2] 15 57 [2] 0b 4a [2] 09 4b [2] 12 4d [2] 0e 4a [2] 12 65 }

  condition:
    any of them
}