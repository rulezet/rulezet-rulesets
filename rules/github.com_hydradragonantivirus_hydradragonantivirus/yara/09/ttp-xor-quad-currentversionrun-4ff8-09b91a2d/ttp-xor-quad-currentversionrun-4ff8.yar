rule TTP_XOR_QUAD_CurrentVersionRun_4ff8 {
  strings:
    $key_4ff8 = { 1c 97 [2] 38 99 [2] 13 b5 [2] 3d 97 [2] 29 8c [2] 26 96 [2] 38 8b [2] 3a 8a [2] 21 8c [2] 3d 8b [2] 21 a4 }

  condition:
    any of them
}