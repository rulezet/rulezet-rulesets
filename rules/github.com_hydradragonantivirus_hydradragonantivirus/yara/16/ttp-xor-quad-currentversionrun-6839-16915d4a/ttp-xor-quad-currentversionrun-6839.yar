rule TTP_XOR_QUAD_CurrentVersionRun_6839 {
  strings:
    $key_6839 = { 3b 56 [2] 1f 58 [2] 34 74 [2] 1a 56 [2] 0e 4d [2] 01 57 [2] 1f 4a [2] 1d 4b [2] 06 4d [2] 1a 4a [2] 06 65 }

  condition:
    any of them
}