rule TTP_XOR_QUAD_CurrentVersionRun_6424 {
  strings:
    $key_6424 = { 37 4b [2] 13 45 [2] 38 69 [2] 16 4b [2] 02 50 [2] 0d 4a [2] 13 57 [2] 11 56 [2] 0a 50 [2] 16 57 [2] 0a 78 }

  condition:
    any of them
}