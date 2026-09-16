rule TTP_XOR_QUAD_CurrentVersionRun_71e8 {
  strings:
    $key_71e8 = { 22 87 [2] 06 89 [2] 2d a5 [2] 03 87 [2] 17 9c [2] 18 86 [2] 06 9b [2] 04 9a [2] 1f 9c [2] 03 9b [2] 1f b4 }

  condition:
    any of them
}