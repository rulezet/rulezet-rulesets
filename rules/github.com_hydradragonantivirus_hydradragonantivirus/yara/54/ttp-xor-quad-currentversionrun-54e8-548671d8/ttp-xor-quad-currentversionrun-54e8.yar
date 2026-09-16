rule TTP_XOR_QUAD_CurrentVersionRun_54e8 {
  strings:
    $key_54e8 = { 07 87 [2] 23 89 [2] 08 a5 [2] 26 87 [2] 32 9c [2] 3d 86 [2] 23 9b [2] 21 9a [2] 3a 9c [2] 26 9b [2] 3a b4 }

  condition:
    any of them
}