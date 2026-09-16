rule TTP_XOR_QUAD_CurrentVersionRun_3f57 {
  strings:
    $key_3f57 = { 6c 38 [2] 48 36 [2] 63 1a [2] 4d 38 [2] 59 23 [2] 56 39 [2] 48 24 [2] 4a 25 [2] 51 23 [2] 4d 24 [2] 51 0b }

  condition:
    any of them
}