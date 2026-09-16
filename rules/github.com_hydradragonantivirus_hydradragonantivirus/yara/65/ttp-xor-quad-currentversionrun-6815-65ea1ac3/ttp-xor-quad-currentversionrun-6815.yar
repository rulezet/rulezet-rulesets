rule TTP_XOR_QUAD_CurrentVersionRun_6815 {
  strings:
    $key_6815 = { 3b 7a [2] 1f 74 [2] 34 58 [2] 1a 7a [2] 0e 61 [2] 01 7b [2] 1f 66 [2] 1d 67 [2] 06 61 [2] 1a 66 [2] 06 49 }

  condition:
    any of them
}