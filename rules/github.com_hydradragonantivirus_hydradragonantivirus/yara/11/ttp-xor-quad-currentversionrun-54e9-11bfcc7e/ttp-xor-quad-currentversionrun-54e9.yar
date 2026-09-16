rule TTP_XOR_QUAD_CurrentVersionRun_54e9 {
  strings:
    $key_54e9 = { 07 86 [2] 23 88 [2] 08 a4 [2] 26 86 [2] 32 9d [2] 3d 87 [2] 23 9a [2] 21 9b [2] 3a 9d [2] 26 9a [2] 3a b5 }

  condition:
    any of them
}