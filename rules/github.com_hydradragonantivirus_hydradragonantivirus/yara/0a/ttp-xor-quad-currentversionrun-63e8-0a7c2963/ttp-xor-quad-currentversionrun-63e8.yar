rule TTP_XOR_QUAD_CurrentVersionRun_63e8 {
  strings:
    $key_63e8 = { 30 87 [2] 14 89 [2] 3f a5 [2] 11 87 [2] 05 9c [2] 0a 86 [2] 14 9b [2] 16 9a [2] 0d 9c [2] 11 9b [2] 0d b4 }

  condition:
    any of them
}