rule TTP_XOR_QUAD_CurrentVersionRun_54fa {
  strings:
    $key_54fa = { 07 95 [2] 23 9b [2] 08 b7 [2] 26 95 [2] 32 8e [2] 3d 94 [2] 23 89 [2] 21 88 [2] 3a 8e [2] 26 89 [2] 3a a6 }

  condition:
    any of them
}