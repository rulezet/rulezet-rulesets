rule TTP_XOR_QUAD_CurrentVersionRun_64e9 {
  strings:
    $key_64e9 = { 37 86 [2] 13 88 [2] 38 a4 [2] 16 86 [2] 02 9d [2] 0d 87 [2] 13 9a [2] 11 9b [2] 0a 9d [2] 16 9a [2] 0a b5 }

  condition:
    any of them
}