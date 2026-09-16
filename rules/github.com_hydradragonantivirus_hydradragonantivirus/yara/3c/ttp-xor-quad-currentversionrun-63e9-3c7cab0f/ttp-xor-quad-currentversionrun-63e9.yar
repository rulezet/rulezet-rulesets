rule TTP_XOR_QUAD_CurrentVersionRun_63e9 {
  strings:
    $key_63e9 = { 30 86 [2] 14 88 [2] 3f a4 [2] 11 86 [2] 05 9d [2] 0a 87 [2] 14 9a [2] 16 9b [2] 0d 9d [2] 11 9a [2] 0d b5 }

  condition:
    any of them
}