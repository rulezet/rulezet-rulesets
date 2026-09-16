rule TTP_XOR_QUAD_CurrentVersionRun_6825 {
  strings:
    $key_6825 = { 3b 4a [2] 1f 44 [2] 34 68 [2] 1a 4a [2] 0e 51 [2] 01 4b [2] 1f 56 [2] 1d 57 [2] 06 51 [2] 1a 56 [2] 06 79 }

  condition:
    any of them
}