rule TTP_XOR_QUAD_CurrentVersionRun_44f8 {
  strings:
    $key_44f8 = { 17 97 [2] 33 99 [2] 18 b5 [2] 36 97 [2] 22 8c [2] 2d 96 [2] 33 8b [2] 31 8a [2] 2a 8c [2] 36 8b [2] 2a a4 }

  condition:
    any of them
}