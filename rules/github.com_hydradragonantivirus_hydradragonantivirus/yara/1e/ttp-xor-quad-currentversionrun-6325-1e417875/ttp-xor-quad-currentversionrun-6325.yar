rule TTP_XOR_QUAD_CurrentVersionRun_6325 {
  strings:
    $key_6325 = { 30 4a [2] 14 44 [2] 3f 68 [2] 11 4a [2] 05 51 [2] 0a 4b [2] 14 56 [2] 16 57 [2] 0d 51 [2] 11 56 [2] 0d 79 }

  condition:
    any of them
}