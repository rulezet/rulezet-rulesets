rule TTP_XOR_QUAD_CurrentVersionRun_7025 {
  strings:
    $key_7025 = { 23 4a [2] 07 44 [2] 2c 68 [2] 02 4a [2] 16 51 [2] 19 4b [2] 07 56 [2] 05 57 [2] 1e 51 [2] 02 56 [2] 1e 79 }

  condition:
    any of them
}