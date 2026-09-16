rule TTP_XOR_QUAD_CurrentVersionRun_2457 {
  strings:
    $key_2457 = { 77 38 [2] 53 36 [2] 78 1a [2] 56 38 [2] 42 23 [2] 4d 39 [2] 53 24 [2] 51 25 [2] 4a 23 [2] 56 24 [2] 4a 0b }

  condition:
    any of them
}