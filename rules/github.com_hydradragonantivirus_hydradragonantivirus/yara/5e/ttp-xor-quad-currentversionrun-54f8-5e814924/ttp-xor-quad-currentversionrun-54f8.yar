rule TTP_XOR_QUAD_CurrentVersionRun_54f8 {
  strings:
    $key_54f8 = { 07 97 [2] 23 99 [2] 08 b5 [2] 26 97 [2] 32 8c [2] 3d 96 [2] 23 8b [2] 21 8a [2] 3a 8c [2] 26 8b [2] 3a a4 }

  condition:
    any of them
}