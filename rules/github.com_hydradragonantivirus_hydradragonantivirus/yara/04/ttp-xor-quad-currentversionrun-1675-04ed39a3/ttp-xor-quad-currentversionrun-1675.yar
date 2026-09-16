rule TTP_XOR_QUAD_CurrentVersionRun_1675 {
  strings:
    $key_1675 = { 45 1a [2] 61 14 [2] 4a 38 [2] 64 1a [2] 70 01 [2] 7f 1b [2] 61 06 [2] 63 07 [2] 78 01 [2] 64 06 [2] 78 29 }

  condition:
    any of them
}