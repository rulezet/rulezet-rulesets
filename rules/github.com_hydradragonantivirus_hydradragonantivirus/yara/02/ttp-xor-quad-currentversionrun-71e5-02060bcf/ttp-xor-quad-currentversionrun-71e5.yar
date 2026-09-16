rule TTP_XOR_QUAD_CurrentVersionRun_71e5 {
  strings:
    $key_71e5 = { 22 8a [2] 06 84 [2] 2d a8 [2] 03 8a [2] 17 91 [2] 18 8b [2] 06 96 [2] 04 97 [2] 1f 91 [2] 03 96 [2] 1f b9 }

  condition:
    any of them
}