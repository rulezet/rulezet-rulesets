rule TTP_XOR_QUAD_CurrentVersionRun_63e5 {
  strings:
    $key_63e5 = { 30 8a [2] 14 84 [2] 3f a8 [2] 11 8a [2] 05 91 [2] 0a 8b [2] 14 96 [2] 16 97 [2] 0d 91 [2] 11 96 [2] 0d b9 }

  condition:
    any of them
}