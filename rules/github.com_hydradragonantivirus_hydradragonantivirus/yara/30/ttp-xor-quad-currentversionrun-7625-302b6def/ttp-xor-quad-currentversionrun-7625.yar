rule TTP_XOR_QUAD_CurrentVersionRun_7625 {
  strings:
    $key_7625 = { 25 4a [2] 01 44 [2] 2a 68 [2] 04 4a [2] 10 51 [2] 1f 4b [2] 01 56 [2] 03 57 [2] 18 51 [2] 04 56 [2] 18 79 }

  condition:
    any of them
}