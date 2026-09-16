rule TTP_XOR_QUAD_CurrentVersionRun_6025 {
  strings:
    $key_6025 = { 33 4a [2] 17 44 [2] 3c 68 [2] 12 4a [2] 06 51 [2] 09 4b [2] 17 56 [2] 15 57 [2] 0e 51 [2] 12 56 [2] 0e 79 }

  condition:
    any of them
}