rule TTP_XOR_QUAD_CurrentVersionRun_3425 {
  strings:
    $key_3425 = { 67 4a [2] 43 44 [2] 68 68 [2] 46 4a [2] 52 51 [2] 5d 4b [2] 43 56 [2] 41 57 [2] 5a 51 [2] 46 56 [2] 5a 79 }

  condition:
    any of them
}