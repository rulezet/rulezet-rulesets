rule TTP_XOR_QUAD_CurrentVersionRun_5825 {
  strings:
    $key_5825 = { 0b 4a [2] 2f 44 [2] 04 68 [2] 2a 4a [2] 3e 51 [2] 31 4b [2] 2f 56 [2] 2d 57 [2] 36 51 [2] 2a 56 [2] 36 79 }

  condition:
    any of them
}