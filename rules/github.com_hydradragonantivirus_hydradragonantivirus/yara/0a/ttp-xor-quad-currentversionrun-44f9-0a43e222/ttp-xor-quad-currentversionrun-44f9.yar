rule TTP_XOR_QUAD_CurrentVersionRun_44f9 {
  strings:
    $key_44f9 = { 17 96 [2] 33 98 [2] 18 b4 [2] 36 96 [2] 22 8d [2] 2d 97 [2] 33 8a [2] 31 8b [2] 2a 8d [2] 36 8a [2] 2a a5 }

  condition:
    any of them
}