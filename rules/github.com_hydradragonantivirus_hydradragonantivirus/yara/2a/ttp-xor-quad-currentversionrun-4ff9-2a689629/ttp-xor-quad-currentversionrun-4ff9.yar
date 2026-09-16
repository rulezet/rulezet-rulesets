rule TTP_XOR_QUAD_CurrentVersionRun_4ff9 {
  strings:
    $key_4ff9 = { 1c 96 [2] 38 98 [2] 13 b4 [2] 3d 96 [2] 29 8d [2] 26 97 [2] 38 8a [2] 3a 8b [2] 21 8d [2] 3d 8a [2] 21 a5 }

  condition:
    any of them
}