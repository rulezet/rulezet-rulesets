rule TTP_XOR_QUAD_CurrentVersionRun_7c25 {
  strings:
    $key_7c25 = { 2f 4a [2] 0b 44 [2] 20 68 [2] 0e 4a [2] 1a 51 [2] 15 4b [2] 0b 56 [2] 09 57 [2] 12 51 [2] 0e 56 [2] 12 79 }

  condition:
    any of them
}