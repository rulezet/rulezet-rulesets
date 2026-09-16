rule TTP_XOR_QUAD_CurrentVersionRun_6415 {
  strings:
    $key_6415 = { 37 7a [2] 13 74 [2] 38 58 [2] 16 7a [2] 02 61 [2] 0d 7b [2] 13 66 [2] 11 67 [2] 0a 61 [2] 16 66 [2] 0a 49 }

  condition:
    any of them
}